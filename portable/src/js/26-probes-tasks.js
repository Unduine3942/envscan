// ---------------------------------------------------------------------------
// 26-probes-tasks: processes, services, scheduled tasks (WMI, local only).
// Port of src/ps/26-probes-system.ps1 (second part); jsSys_*/jsNet_* helpers live in
// 26-probes-system.js and 25-probes-network.js.
// ---------------------------------------------------------------------------

function jsSys_cmdline(value) {
    // Redact before cutting: a cut could split a secret from the option that marks it.
    var line = protectEsCommandLine(jsSys_str(value));
    if (line && line.length > 500) { line = line.substring(0, 500) + "..."; }
    return line ? line : null;
}

function jsSys_process(item) {
    return {
        pid: parseInt(item.ProcessId, 10) || 0, ppid: parseInt(item.ParentProcessId, 10) || 0, name: jsSys_str(item.Name), user: null,
        path: item.ExecutablePath ? String(item.ExecutablePath) : null, cmdline: jsSys_cmdline(item.CommandLine)
    };
}

function probe_proc_list() {
    var r = newEsResult();
    var items = addEsCimItems(r, "Win32_Process", "root/cimv2", "", ["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine"]);
    var sorted = jsNet_stableSort(items, function (item) { return parseInt(item.ProcessId, 10) || 0; }, jsNet_numCompare);
    var processes = [];
    var visible = 0;
    for (var i = 0; i < sorted.length && i < ES_MAX_PROCESSES; i++) {
        var process = jsSys_process(sorted[i]);
        if (process.path) { visible++; }
        processes.push(process);
    }
    r.data.count = items.length;
    r.data.processes = processes;
    r.data.truncated = (items.length > ES_MAX_PROCESSES);
    r.data.visible_details = visible;
    return r;
}

function jsSys_service(item) {
    return {
        name: jsSys_str(item.Name), display: jsSys_str(item.DisplayName), state: jsSys_str(item.State), start_mode: jsSys_str(item.StartMode),
        account: jsSys_str(item.StartName), path: protectEsCommandLine(jsSys_str(item.PathName)), pid: parseInt(item.ProcessId, 10) || 0
    };
}

function probe_svc_list() {
    var r = newEsResult();
    var items = addEsCimItems(r, "Win32_Service", "root/cimv2", "", ["Name", "DisplayName", "State", "StartMode", "StartName", "PathName", "ProcessId"]);
    var sorted = jsNet_stableSort(items, function (item) { return jsSys_str(item.Name); }, jsNet_textCompare);
    var services = [];
    var running = 0;
    for (var i = 0; i < sorted.length; i++) {
        if (i < ES_MAX_SERVICES) { services.push(jsSys_service(sorted[i])); }
        if (jsSys_str(sorted[i].State) == "Running") { running++; }
    }
    r.data.manager = "scm";
    r.data.count = items.length;
    r.data.running = running;
    r.data.services = services;
    r.data.truncated = (items.length > ES_MAX_SERVICES);
    return r;
}

function jsSys_taskActions(actions) {
    // The action command lines, or null when the WMI worker could not deliver them: it passes
    // embedded objects (MSFT_TaskAction) as null, so an action list holding null is unknown.
    var out = [];
    var list = (actions === null || actions === undefined) ? [] : jsNet_psArray(actions);
    for (var i = 0; i < list.length; i++) {
        var action = list[i];
        if (action === null || typeof action != "object") { return null; }
        if (!action.Execute) { continue; }
        out.push(protectEsCommandLine(esTrim(jsSys_str(action.Execute) + " " + jsSys_str(action.Arguments))));
    }
    return out;
}

function jsSys_task(item, path) {
    var states = { s0: "unknown", s1: "disabled", s2: "queued", s3: "ready", s4: "running" };
    var state = states["s" + String(parseInt(item.State, 10) || 0)];
    var principal = (item.Principal && typeof item.Principal == "object") ? jsSys_str(item.Principal.UserId) : null;
    return { name: jsSys_str(item.TaskName), path: path, state: (state === undefined) ? null : state,
        actions: jsSys_taskActions(item.Actions), principal: principal };
}

function jsSys_taskGaps(r, tasks) {
    // Facts the WMI worker could not deliver (embedded objects) are unknown, never "none".
    var actions = 0;
    var principals = 0;
    for (var i = 0; i < tasks.length; i++) {
        if (tasks[i].actions === null) { actions++; }
        if (tasks[i].principal === null) { principals++; }
    }
    if (actions + principals === 0) { return; }
    addEsNote(r, "task actions (" + actions + ") and principals (" + principals + ") are not available in the WSH port (embedded WMI objects): unknown", "partial");
}

function probe_sched_tasks() {
    var r = newEsResult();
    var query = getEsCimSafe("MSFT_ScheduledTask", "root/Microsoft/Windows/TaskScheduler", "", ["TaskName", "TaskPath", "State", "Actions", "Principal"], 60);
    r.sources.push("CIM root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask");
    if (query.status != "ok") { r.status = query.status; r.error = query.error; return r; }
    var sorted = jsNet_stableSort(query.items, function (item) { return jsSys_str(item.TaskPath) + jsSys_str(item.TaskName); }, jsNet_textCompare);
    var microsoft = 0;
    var tasks = [];
    for (var i = 0; i < sorted.length; i++) {
        var path = jsSys_str(sorted[i].TaskPath);
        if (esStartsWith(esLower(path), "\\microsoft\\")) { microsoft++; continue; }
        if (tasks.length < ES_MAX_TASKS) { tasks.push(jsSys_task(sorted[i], path)); }
    }
    r.data.count = query.items.length;
    r.data.microsoft_task_count = microsoft;
    r.data.tasks = tasks;
    jsSys_taskGaps(r, tasks);
    r.data.user_crontab = [];
    r.data.timers = [];
    r.data.linger = null;
    return r;
}
