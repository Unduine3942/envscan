// ---------------------------------------------------------------------------
// 11a-exec: external commands (timeouts, tree stop) and decoding of their output.
// Port of the command part of src/ps/11-exec.ps1.
//
// How a command runs (invokeEsCommand): WScript.Shell.Exec of
//   "<System32>\cmd.exe" /d /v:off /s /c ">"<tmp>\cN.out" 2>"<tmp>\cN.err" <"<tmp>\stdin.empty" "<program>" <args>"
// with the current directory set to the system drive root (or the given folder) only for the
// Exec call, and the environment of ES_CHILD_ENV (enterEsChildEnv) on top of the allowlisted
// variables only (stripEsChildEnv, spec [child_env_keep]). /d skips the AutoRun
// commands, /v:off keeps "!" literal, /s takes the line as it is. Exec pipes are never read: a
// surviving grandchild could hold them open forever.
// Argument safety: cmd.exe (and Exec) expand %NAME% even inside quotes, and a double quote
// would end the quoting, so a program path or an argument holding % or ", a line break or NUL is
// refused ("not run: ..."). An argument with white space or & | < > ^ is passed in double quotes,
// which keeps those characters literal for cmd.exe; a batch file (.cmd/.bat) refuses
// % & | < > ^ in arguments as the ps1 does, because the batch would expand them again.
// Output encoding: console programs write redirected output in the OEM code page. FSO reads
// the ANSI code page, which is exact for ASCII, and for any text when ANSI and OEM code pages
// are the same (all CJK systems). Otherwise the bytes are read exactly (esReadBytesExact) and
// mapped with a table for OEM 437 and 850; other OEM code pages give "?" for non-ASCII bytes.
// ---------------------------------------------------------------------------

var ES_ARG_REFUSED_RE = /[%"\r\n\x00]/;
var ES_ARG_QUOTE_RE = /[\s&|<>^]/;
var ES_BATCH_REFUSED_RE = /[%&|<>^\r\n]/;
var ES_OUTPUT_MAX_BYTES = 8388608;
var ES_CODEPAGES = null;
var ES_OEM_TABLES = {
    "437": [199, 252, 233, 226, 228, 224, 229, 231, 234, 235, 232, 239, 238, 236, 196, 197, 201, 230, 198, 244,
        246, 242, 251, 249, 255, 214, 220, 162, 163, 165, 8359, 402, 225, 237, 243, 250, 241, 209, 170, 186, 191,
        8976, 172, 189, 188, 161, 171, 187, 9617, 9618, 9619, 9474, 9508, 9569, 9570, 9558, 9557, 9571, 9553, 9559,
        9565, 9564, 9563, 9488, 9492, 9524, 9516, 9500, 9472, 9532, 9566, 9567, 9562, 9556, 9577, 9574, 9568, 9552,
        9580, 9575, 9576, 9572, 9573, 9561, 9560, 9554, 9555, 9579, 9578, 9496, 9484, 9608, 9604, 9612, 9616, 9600,
        945, 223, 915, 960, 931, 963, 181, 964, 934, 920, 937, 948, 8734, 966, 949, 8745, 8801, 177, 8805, 8804,
        8992, 8993, 247, 8776, 176, 8729, 183, 8730, 8319, 178, 9632, 160],
    "850": [199, 252, 233, 226, 228, 224, 229, 231, 234, 235, 232, 239, 238, 236, 196, 197, 201, 230, 198, 244,
        246, 242, 251, 249, 255, 214, 220, 248, 163, 216, 215, 402, 225, 237, 243, 250, 241, 209, 170, 186, 191,
        174, 172, 189, 188, 161, 171, 187, 9617, 9618, 9619, 9474, 9508, 193, 194, 192, 169, 9571, 9553, 9559,
        9565, 162, 165, 9488, 9492, 9524, 9516, 9500, 9472, 9532, 227, 195, 9562, 9556, 9577, 9574, 9568, 9552,
        9580, 164, 240, 208, 202, 203, 200, 305, 205, 206, 207, 9496, 9484, 9608, 9604, 166, 204, 9600, 211, 223,
        212, 210, 245, 213, 181, 254, 222, 218, 219, 217, 253, 221, 175, 180, 173, 177, 8215, 190, 182, 167, 247,
        184, 176, 168, 183, 185, 179, 178, 9632, 160]
};

function getEsErrorStatus(message) {
    if (!message) { return "error"; }
    var text = String(message);
    if (/access (is )?denied|unauthorized|requires elevat|administrator privilege|0x80070005|0x80041003/i.test(text)) { return "denied"; }
    if (/invalid (class|namespace)|not found|cannot find|does not exist|0x80041010|0x8004100e/i.test(text)) { return "not_found"; }
    if (/timed? ?out|timeout/i.test(text)) { return "timeout"; }
    return "error";
}

// ------------------------------------------------------------------ argument strings

function esQuoteArg(arg, pattern) {
    // CRT quoting: the argument in double quotes, trailing backslashes doubled.
    if (arg === "") { return "\"\""; }
    if (!pattern.test(arg)) { return arg; }
    var escaped = arg.replace(/(\\*)"/g, "$1$1\\\"").replace(/(\\+)$/, "$1$1");
    return "\"" + escaped + "\"";
}

function convertToEsArgString(args) {
    // The ps1 command text (ConvertTo-EsArgString): quoted only for white space or a quote.
    var quoted = [];
    var list = args || [];
    for (var i = 0; i < list.length; i++) {
        var arg = list[i] === null || list[i] === undefined ? "" : String(list[i]);
        quoted.push(esQuoteArg(arg, /[\s"]/));
    }
    return quoted.join(" ");
}

function esCmdArgString(args) {
    // The arguments as cmd.exe passes them on unchanged (callers refused % " and line breaks).
    var quoted = [];
    var list = args || [];
    for (var i = 0; i < list.length; i++) {
        var arg = list[i] === null || list[i] === undefined ? "" : String(list[i]);
        quoted.push(esQuoteArg(arg, ES_ARG_QUOTE_RE));
    }
    return quoted.join(" ");
}

function getEsLaunch(filePath, args) {
    // What runs and the command text (as the ps1 shows it), or the reason it is not run.
    var argString = convertToEsArgString(args);
    var launch = { file: filePath, args: argString, error: null, line: null };
    var path = String(filePath || "");
    if (!/^[A-Za-z]:\\/.test(path)) { launch.error = "not run: not an absolute path"; return launch; }
    var link = getEsPathLinkReason(path);
    if (link) { launch.error = "not run: " + link; return launch; }
    var list = args || [];
    var batch = esEndsWithI(path, ".cmd") || esEndsWithI(path, ".bat");
    var refuse = batch ? ES_BATCH_REFUSED_RE : ES_ARG_REFUSED_RE;
    for (var i = 0; i < list.length; i++) {
        if (list[i] !== null && list[i] !== undefined && refuse.test(String(list[i]))) {
            launch.error = batch ? "not run: the batch file command line holds a cmd.exe special character"
                : "not run: an argument holds a character cmd.exe would expand (% \" or a line break)";
            return launch;
        }
    }
    if (ES_ARG_REFUSED_RE.test(path)) { launch.error = "not run: the program path holds % or a quote"; return launch; }
    launch.line = "\"" + path + "\"" + (list.length ? " " + esCmdArgString(list) : "");
    if (batch) {
        launch.file = getEsSystemTool("cmd.exe");
        if (!launch.file) { launch.error = ES_NO_CMD_ERROR; return launch; }
        launch.args = "/d /v:off /s /c \"" + esTrim("\"" + path + "\" " + argString) + "\"";
    }
    return launch;
}

// ------------------------------------------------------------------ running a child

function esStartChild(commandLine, cwd) {
    // WshShell.Exec with the current directory set and the environment reduced to the
    // allowlist (stripEsChildEnv) for the start only: the child copies both when it is created,
    // so this process gets them back before the child is waited for.
    var previous = ES_SHELL.CurrentDirectory;
    var child = null;
    var removed = stripEsChildEnv();
    try {
        if (cwd) { ES_SHELL.CurrentDirectory = cwd; }
        child = ES_SHELL.Exec(commandLine);
    } finally {
        restoreEsChildEnv(removed);
        try { ES_SHELL.CurrentDirectory = previous; } catch (e) { /* the old folder is gone */ }
    }
    try { child.StdIn.Close(); } catch (e2) { /* already closed */ }
    return child;
}

function esWaitChild(child, timeoutMs) {
    // true when the child exited within timeoutMs.
    var start = new Date().getTime();
    var pause = 10;
    while (child.Status === 0) {
        if (new Date().getTime() - start >= timeoutMs) { return false; }
        WScript.Sleep(pause);
        if (pause < 100) { pause += 10; }
    }
    return true;
}

var ES_NO_CMD_ERROR = "not run: the Windows folder is not a trusted local path (no cmd.exe)";

function esCmdLine(inner) {
    // cmd.exe from the trusted Windows folder (getEsSystemTool), never one named by the environment.
    var cmd = getEsSystemTool("cmd.exe");
    if (!cmd) { throw new Error(ES_NO_CMD_ERROR); }
    return "\"" + cmd + "\" /d /v:off /s /c \"" + inner + "\"";
}

function esDeleteFile(path) {
    try { if (ES_FSO.FileExists(path)) { ES_FSO.DeleteFile(path, true); } } catch (e) { writeEsLog("cannot delete " + path + ": " + esErrorText(e)); }
}

function invokeEsCommand(filePath, args, timeoutSec, encoding, maxLines, workingDirectory) {
    // Runs one external command: empty stdin, cwd = system drive root, timeout, whole process
    // tree stopped on timeout. Never throws.
    var timeout = timeoutSec > 0 ? timeoutSec : ES_OPT.timeout;
    ES_CMD_SEQ++;
    var base = esJoinPath(ES_TMP || "", "c" + ES_CMD_SEQ);
    var launch = getEsLaunch(filePath, args || []);
    var result = { command: esTrim(launch.file + " " + launch.args), exit_code: null, stdout: "", stderr: "",
        timed_out: false, error: launch.error, duration_ms: 0 };
    if (launch.error) { return result; }
    if (!ES_TMP) { result.error = "no temporary folder"; return result; }
    var start = getEsUtc();
    try {
        // Redirections first: "echo x >f" would keep the space before ">".
        var redirect = ">\"" + base + ".out\" 2>\"" + base + ".err\" <\"" + ES_EMPTY_IN + "\" ";
        var line = esCmdLine(redirect + launch.line);
        var created = { from: new Date().getTime(), to: 0 };
        var child = esStartChild(line, workingDirectory || ES_CHILD_CWD);
        created.to = new Date().getTime();
        if (esWaitChild(child, timeout * 1000)) { result.exit_code = child.ExitCode; }
        else {
            result.timed_out = true;
            stopEsProcessTree(child.ProcessID, child, created);
            writeEsLog("timeout after " + timeout + "s: " + result.command);
        }
    } catch (e) {
        result.error = esErrorText(e);
    }
    result.stdout = readEsCommandOutput(base + ".out", encoding || "Oem", maxLines || 4000);
    result.stderr = readEsCommandOutput(base + ".err", encoding || "Oem", maxLines || 4000);
    esDeleteFile(base + ".out");
    esDeleteFile(base + ".err");
    result.duration_ms = getEsElapsedMs(start);
    return result;
}

function getEsCommandText(result) {
    // stdout and stderr together (many tools print versions on stderr).
    var parts = [];
    if (result.stdout) { parts.push(result.stdout); }
    if (result.stderr) { parts.push(result.stderr); }
    return esTrim(parts.join("\n"));
}

// ------------------------------------------------------------------ process tree

function selectEsDescendants(processId, snapshot) {
    // processId and its descendants in a Win32_Process snapshot ({ProcessId, ParentProcessId,
    // CreationDate}). A child counts only when created no earlier than its parent (PID reuse);
    // without a creation time a process is never treated as a descendant.
    var created = {};
    var children = {};
    var list = snapshot || [];
    for (var i = 0; i < list.length; i++) {
        var item = list[i];
        created["p" + item.ProcessId] = convertFromEsCimDate(item.CreationDate);
        var parent = "p" + item.ParentProcessId;
        if (!children[parent]) { children[parent] = []; }
        children[parent].push(Number(item.ProcessId));
    }
    var ids = [Number(processId)];
    for (var index = 0; index < ids.length && index < 500; index++) {
        var parentTime = created["p" + ids[index]];
        if (!parentTime) { continue; }
        var kids = children["p" + ids[index]] || [];
        for (var k = 0; k < kids.length; k++) {
            if (esContains(ids, kids[k])) { continue; }
            var childTime = created["p" + kids[k]];
            if (childTime && childTime.getTime() >= parentTime.getTime()) { ids.push(kids[k]); }
        }
    }
    return ids;
}

var ES_CREATION_SLACK_MS = 500;

function stopEsProcessTree(processId, child, created) {
    // The WMI worker takes one Win32_Process snapshot and stops the tree (selectEsDescendants),
    // but only when the process with that PID was created while we started the child
    // (created = {from, to} in ms since 1970; a recycled PID is never stopped). The Exec object
    // stops the root when the worker could not.
    var window = created || { from: 0, to: 0 };
    try {
        var reply = invokeEsWorker(["tree-stop", String(processId), String(Math.max(0, window.from - ES_CREATION_SLACK_MS)),
            String(window.to + ES_CREATION_SLACK_MS)], 10);
        if (reply.status !== "ok") { writeEsLog("process tree stop: " + reply.error); }
    } catch (e) {
        writeEsLog("process snapshot failed; only the timed-out process is stopped: " + esErrorText(e));
    }
    try { if (child && child.Status === 0) { child.Terminate(); } } catch (e2) { /* already gone */ }
}

// ------------------------------------------------------------------ reading output

function getEsCodePages() {
    // {acp, oemcp} from the registry, once.
    if (ES_CODEPAGES === null) {
        var key = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage";
        ES_CODEPAGES = { acp: String(getEsRegValue(key, "ACP") || ""), oemcp: String(getEsRegValue(key, "OEMCP") || "") };
    }
    return ES_CODEPAGES;
}

function esReadAnsi(path, maxBytes) {
    // The file decoded in the ANSI code page (FSO), at most maxBytes characters.
    var stream = ES_FSO.OpenTextFile(path, 1, false, 0);
    try { return stream.AtEndOfStream ? "" : stream.Read(maxBytes); } finally { stream.Close(); }
}

function esDecodeOem(bytes) {
    var table = ES_OEM_TABLES[getEsCodePages().oemcp] || null;
    var out = [];
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i];
        out.push(b < 128 ? String.fromCharCode(b) : (table ? String.fromCharCode(table[b - 128]) : "?"));
    }
    return out.join("");
}

function esReadOemText(path, maxBytes) {
    var ansi = esReadAnsi(path, maxBytes);
    if (!/[^\x00-\x7f]/.test(ansi)) { return ansi; }
    var pages = getEsCodePages();
    if (pages.acp !== "" && pages.acp === pages.oemcp) { return ansi; }
    return esDecodeOem(esReadBytesExact(path, maxBytes).bytes);
}

function esReadUnicode(path, maxChars) {
    var stream = ES_FSO.OpenTextFile(path, 1, false, -1);
    try { return stream.AtEndOfStream ? "" : stream.Read(maxChars); } finally { stream.Close(); }
}

function esDecodeFile(path, encoding, maxBytes) {
    var enc = esLower(encoding);
    if (enc === "unicode") { return esReadUnicode(path, maxBytes); }
    if (enc === "utf8") {
        var read = esReadBytesExact(path, maxBytes);
        var text = read.exact ? esDecodeUtf8Strict(esStripUtf8Bom(read.bytes)) : null;
        return text === null ? esReadAnsi(path, maxBytes) : text;
    }
    if (enc === "oem") { return esReadOemText(path, maxBytes); }
    return esReadAnsi(path, maxBytes);
}

function esSplitLines(text, maxLines) {
    // Get-Content lines: CRLF, LF or CR end a line; no empty line after a final line end.
    var lines = String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
    if (lines.length > 0 && lines[lines.length - 1] === "") { lines.pop(); }
    return maxLines && lines.length > maxLines ? lines.slice(0, maxLines) : lines;
}

function readEsCommandOutput(path, encoding, maxLines) {
    try {
        if (!ES_FSO.FileExists(path) || ES_FSO.GetFile(path).Size === 0) { return ""; }
        return esSplitLines(esDecodeFile(path, encoding, ES_OUTPUT_MAX_BYTES), maxLines).join("\n");
    } catch (e) { return ""; }
}
