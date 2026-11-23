// ---------------------------------------------------------------------------
// 11f-childenv: the environment every child sees (spec/child_env.toml, DEVELOPING.md hard rule 6).
// Children inherit this process environment, so it is changed for the Exec call only:
//   enterEsChildEnv / exitEsChildEnv   the [child_env] values for the whole scan
//   stripEsChildEnv / restoreEsChildEnv  per child start: every variable outside
//       [child_env_keep], [child_env] and the call's extras (withEsChildExtras) is removed; kept
//       path variables are vetted without touching the path (UNC, mapped network drive, device or
//       relative path, credential store): home_paths -> an empty folder in the scanner temp
//       (TMP/TEMP/TMPDIR -> the temp folder itself), path_lists -> refused entries dropped (an
//       empty list removed), any other absolute path -> removed. The result is listed again
//       before the start; anything left over restores the environment and throws (fail closed).
// Values are restored exactly: an empty variable ("X=") is not an unset one.
// ---------------------------------------------------------------------------

// Lower-case names a caller sets for its next child only (git overrides, the worker mark):
// kept by stripEsChildEnv like the allowlist, never vetted. Changed only through withEsChildExtras.
var ES_CHILD_EXTRA_NAMES = {};
var ES_CHILD_VET_CACHE = {};
var ES_CHILD_TEMP_NAMES = ["TMP", "TEMP", "TMPDIR"];

// ------------------------------------------------------------------ exact values

function listEsProcessEnv() {
    // [[name, value], ...] of this process, names as Windows spells them.
    var list = [];
    var items = new Enumerator(ES_PROCESS_ENV);
    for (; !items.atEnd(); items.moveNext()) {
        var entry = String(items.item());
        var eq = entry.indexOf("=", 1);
        if (eq > 0) { list.push([entry.substr(0, eq), entry.substr(eq + 1)]); }
    }
    return list;
}

function getEsEnvExact(name) {
    // The value of a process variable ("" for an empty one) or null when it is unset.
    var lower = String(name).toLowerCase();
    var list = listEsProcessEnv();
    for (var i = 0; i < list.length; i++) {
        if (list[i][0].toLowerCase() === lower) { return list[i][1]; }
    }
    return null;
}

function removeEsEnvStrict(name) {
    // Throws when the variable cannot be removed (the caller verifies the result as well).
    ES_PROCESS_ENV.Remove(String(name));
}

function setEsEnvExact(name, value) {
    // value exactly ("" stays an empty variable); null removes the variable. Throws on failure.
    if (value === null || value === undefined) { removeEsEnvStrict(name); }
    else { ES_PROCESS_ENV.Item(String(name)) = String(value); }
}

function restoreEsChildEnv(changes) {
    // Puts back [[name, previous value or null], ...] (last change first). One variable that
    // cannot be restored does not stop the others; it is logged.
    for (var i = changes.length - 1; i >= 0; i--) {
        try { setEsEnvExact(changes[i][0], changes[i][1]); }
        catch (e) { writeEsLog("cannot restore environment variable " + changes[i][0] + ": " + esErrorText(e)); }
    }
}

// ------------------------------------------------------------------ the scan-wide values

function enterEsChildEnv() {
    // The [child_env] values for every child; exitEsChildEnv restores the previous values.
    var saved = [];
    var names = esKeys(ES_CHILD_ENV);
    for (var i = 0; i < names.length; i++) {
        saved.push([names[i], getEsEnvExact(names[i])]);
        setEsEnvValue(names[i], ES_CHILD_ENV[names[i]] === null ? "" : String(ES_CHILD_ENV[names[i]]));
    }
    ES_CHILD_ENV_SAVED = saved;
}

function exitEsChildEnv() {
    restoreEsChildEnv(esIsArray(ES_CHILD_ENV_SAVED) ? ES_CHILD_ENV_SAVED : []);
    ES_CHILD_ENV_SAVED = [];
}

function withEsChildExtras(names, action) {
    // Runs action() with names added to ES_CHILD_EXTRA_NAMES; the previous set is restored.
    var previous = ES_CHILD_EXTRA_NAMES;
    var next = {};
    var old = esKeys(previous);
    var i;
    for (i = 0; i < old.length; i++) { next[old[i]] = true; }
    for (i = 0; i < names.length; i++) { next[String(names[i]).toLowerCase()] = true; }
    ES_CHILD_EXTRA_NAMES = next;
    try { return action(); } finally { ES_CHILD_EXTRA_NAMES = previous; }
}

// ------------------------------------------------------------------ allowlist and vetting

function testEsChildEnvOwn(lower) {
    // A name the scanner sets itself ([child_env] or the call's extras): kept, not vetted.
    if (lower.charAt(0) === "=" || esHas(ES_CHILD_EXTRA_NAMES, lower)) { return true; }
    var own = esKeys(ES_CHILD_ENV);
    for (var i = 0; i < own.length; i++) { if (own[i].toLowerCase() === lower) { return true; } }
    return false;
}

function testEsChildEnvKept(name) {
    // spec/child_env.toml [child_env_keep] (case-insensitive), the [child_env] names and the
    // per-call extras. Names starting with "=" (cmd.exe drive folders) are never touched.
    var lower = String(name).toLowerCase();
    if (testEsChildEnvOwn(lower)) { return true; }
    var i;
    for (i = 0; i < ES_CHILD_ENV_KEEP_NAMES.length; i++) {
        if (ES_CHILD_ENV_KEEP_NAMES[i].toLowerCase() === lower) { return true; }
    }
    for (i = 0; i < ES_CHILD_ENV_KEEP_PREFIXES.length; i++) {
        if (lower.indexOf(ES_CHILD_ENV_KEEP_PREFIXES[i].toLowerCase()) === 0) { return true; }
    }
    return false;
}

function testEsChildPathRefused(path) {
    // Text only, nothing is looked at: not a local path (UNC, mapped network drive, device,
    // relative) or in a credential store.
    var p = String(path).replace(/^\s*"/, "").replace(/"\s*$/, "");
    return getEsNonLocalReason(p) !== null || getEsCredentialFolder(p) !== null;
}

function getEsChildHome(name) {
    // The replacement for a refused home_paths value: the scanner temp folder for the temp
    // variables, else an empty folder in it (created once); null when there is none.
    if (!ES_TMP) { return null; }
    if (esContainsI(ES_CHILD_TEMP_NAMES, name)) { return ES_TMP; }
    var home = esJoinPath(ES_TMP, "childhome");
    try { if (!ES_FSO.FolderExists(home)) { ES_FSO.CreateFolder(home); } }
    catch (e) { writeEsLog("cannot create " + home + ": " + esErrorText(e)); return null; }
    return home;
}

function jsEnv_vetList(value) {
    // A ";" list without its refused entries, or null when none is left.
    var parts = String(value).split(";");
    var kept = [];
    for (var i = 0; i < parts.length; i++) {
        if (!/^\s*$/.test(parts[i]) && !testEsChildPathRefused(parts[i])) { kept.push(parts[i]); }
    }
    return kept.length ? kept.join(";") : null;
}

function getEsChildValue(name, value) {
    // What a child gets for a kept user variable (spec home_paths, path_lists, other paths).
    if (esContainsI(ES_CHILD_ENV_HOME_PATHS, name)) {
        return value === "" || !testEsChildPathRefused(value) ? value : getEsChildHome(name);
    }
    if (esContainsI(ES_CHILD_ENV_PATH_LISTS, name)) { return value === "" ? value : jsEnv_vetList(value); }
    if (/^(?:[A-Za-z]:[\\\/]|[\\\/])/.test(value) && testEsChildPathRefused(value)) { return null; }
    return value;
}

function getEsChildValueCached(name, value) {
    var key = "k" + String(name).toLowerCase() + "\n" + (ES_TMP || "") + "\n" + value;
    if (!esHas(ES_CHILD_VET_CACHE, key)) { ES_CHILD_VET_CACHE[key] = getEsChildValue(name, value); }
    return ES_CHILD_VET_CACHE[key];
}

function getEsChildEnvPlan(list) {
    // [[name, current value, child value or null], ...] for every variable that changes.
    var plan = [];
    for (var i = 0; i < list.length; i++) {
        var name = list[i][0], value = list[i][1];
        if (!testEsChildEnvKept(name)) { plan.push([name, value, null]); continue; }
        if (testEsChildEnvOwn(name.toLowerCase())) { continue; }
        var next = getEsChildValueCached(name, value);
        if (next !== value) { plan.push([name, value, next]); }
    }
    return plan;
}

// ------------------------------------------------------------------ one child start

function testEsChildEnvApplied(plan) {
    // Lists the environment again: throws when a variable a child may not see is still there
    // or a vetted value is not what the plan set.
    var expected = {}, seen = {};
    var i;
    for (i = 0; i < plan.length; i++) { expected["k" + plan[i][0].toLowerCase()] = plan[i][2]; }
    var list = listEsProcessEnv();
    for (i = 0; i < list.length; i++) {
        var key = "k" + list[i][0].toLowerCase();
        var wanted = esHas(expected, key) ? expected[key] : list[i][1];
        if (!testEsChildEnvKept(list[i][0]) || wanted === null) { throw new Error("variable still set: " + list[i][0]); }
        if (wanted !== list[i][1]) { throw new Error("variable not set: " + list[i][0]); }
        seen[key] = true;
    }
    var planned = esKeys(expected);
    for (i = 0; i < planned.length; i++) {
        var gone = !esHas(seen, planned[i]);
        if (gone && expected[planned[i]] !== null) { throw new Error("variable not set: " + planned[i].substr(1)); }
    }
}

function stripEsChildEnv() {
    // Applies the allowlist and the path vetting for one child start; returns the changes for
    // restoreEsChildEnv. On any failure (listing, a removal, the check afterwards) the
    // environment is restored and an error thrown, so the child is never started.
    var changes = [];
    try {
        var plan = getEsChildEnvPlan(listEsProcessEnv());
        for (var i = 0; i < plan.length; i++) {
            changes.push([plan[i][0], plan[i][1]]);
            setEsEnvExact(plan[i][0], plan[i][2]);
        }
        testEsChildEnvApplied(plan);
    } catch (e) {
        restoreEsChildEnv(changes);
        throw new Error("child environment not applied, command not run: " + esErrorText(e));
    }
    return changes;
}
