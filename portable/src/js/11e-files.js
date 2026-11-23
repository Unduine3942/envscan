// ---------------------------------------------------------------------------
// 11e-files: reading files and folders. Port of Read-EsTextFile, Read-EsBytes,
// Get-EsDirEntries, Test-EsWritableDir and Get-EsPeMachine of src/ps/11-exec.ps1.
//
// Exact bytes through FSO (verified on Windows 11): a stream opened in Unicode mode
// (OpenTextFile(path, 1, false, -1)) on any file returns each byte pair as one UTF-16 code unit,
// NUL bytes and CR/LF included, with two exceptions handled here: a leading FF FE pair is taken as
// a BOM and skipped (detected with Skip over the whole file, only when the first byte is not
// ASCII), and an odd final byte is dropped (recovered from an ANSI-mode read when it is ASCII,
// else the read is marked inexact).
// Text files (readEsTextFile): a UTF-16 BOM is read as UTF-16, a UTF-8 BOM or valid UTF-8 is
// decoded exactly, anything else in the ANSI code page (as Get-Content does without a BOM).
// ---------------------------------------------------------------------------

var ES_MULTIBYTE_ACP = ["932", "936", "949", "950", "1361", "54936", "65001"];

function testEsPlaceholderFile(item) {
    // OneDrive/cloud placeholders download when read: OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS.
    var attributes = 0;
    try { attributes = item.Attributes; } catch (e) { return false; }
    return (attributes & 4096) !== 0 || (attributes & 262144) !== 0 || (attributes & 4194304) !== 0;
}

// ------------------------------------------------------------------ bytes

function esHasUtf16Bom(path, size) {
    if (size < 2) { return false; }
    var ansi = ES_FSO.OpenTextFile(path, 1, false, 0);
    var first = "";
    try { first = ansi.AtEndOfStream ? "" : ansi.Read(1); } finally { ansi.Close(); }
    if (first !== "" && first.charCodeAt(0) < 128) { return false; }
    var stream = ES_FSO.OpenTextFile(path, 1, false, -1);
    try {
        var chars = Math.floor(size / 2) - 1;
        if (chars > 0) { stream.Skip(chars); }
        return stream.AtEndOfStream;
    } finally { stream.Close(); }
}

function esLastOddByte(path, size) {
    // The final byte of an odd-sized file when it can be known exactly (ASCII), else -1.
    var multi = esContains(ES_MULTIBYTE_ACP, getEsCodePages().acp);
    var stream = ES_FSO.OpenTextFile(path, 1, false, 0);
    var last = "";
    try {
        if (!multi) { if (size > 1) { stream.Skip(size - 1); } last = stream.AtEndOfStream ? "" : stream.Read(1); }
        else { var all = stream.AtEndOfStream ? "" : stream.ReadAll(); last = all.substr(all.length - 1); }
    } finally { stream.Close(); }
    if (last === "") { return -1; }
    var code = last.charCodeAt(0);
    return code < (multi ? 48 : 128) ? code : -1;
}

function esReadBytesExact(path, maxBytes) {
    // {bytes, size, exact}: the first maxBytes bytes of a file.
    var size = ES_FSO.GetFile(path).Size;
    var want = Math.min(size, maxBytes);
    var bytes = [];
    var bom = want > 0 && esHasUtf16Bom(path, size);
    if (bom) { bytes.push(255, 254); }
    var chars = Math.ceil((want - bytes.length) / 2);
    var text = chars > 0 ? esReadUnicode(path, chars) : "";
    for (var i = 0; i < text.length; i++) {
        var code = text.charCodeAt(i);
        bytes.push(code & 255, code >> 8);
    }
    var exact = true;
    if (bytes.length < want) {
        var lastByte = esLastOddByte(path, size);
        if (lastByte >= 0) { bytes.push(lastByte); } else { exact = false; }
    }
    if (bytes.length > want) { bytes.length = want; }
    return { bytes: bytes, size: size, exact: exact };
}

function readEsBytes(path, count) {
    // The first count bytes (default 4096) as numbers; an unknown final odd byte is left out.
    return esReadBytesExact(String(path), count > 0 ? count : 4096).bytes;
}

// ------------------------------------------------------------------ UTF-8

function esStripUtf8Bom(bytes) {
    return bytes.length >= 3 && bytes[0] === 239 && bytes[1] === 187 && bytes[2] === 191 ? bytes.slice(3) : bytes;
}

function esUtf8Sequence(bytes, i) {
    // [code point, length] of the sequence at i, or null when malformed.
    var b = bytes[i];
    var more = b < 128 ? 0 : (b >= 194 && b < 224 ? 1 : (b >= 224 && b < 240 ? 2 : (b >= 240 && b < 245 ? 3 : -1)));
    if (more < 0) { return null; }
    var code = more === 0 ? b : (b & (more === 1 ? 31 : (more === 2 ? 15 : 7)));
    for (var k = 1; k <= more; k++) {
        var c = bytes[i + k];
        if (c === undefined || c < 128 || c > 191) { return null; }
        code = code * 64 + (c - 128);
    }
    var min = [0, 128, 2048, 65536][more];
    if (code < min || code > 1114111 || (code >= 55296 && code <= 57343)) { return null; }
    return [code, more + 1];
}

function esDecodeUtf8Strict(bytes) {
    // The text of valid UTF-8 bytes, or null.
    var out = [];
    var i = 0;
    while (i < bytes.length) {
        var seq = esUtf8Sequence(bytes, i);
        if (seq === null) { return null; }
        var code = seq[0];
        if (code < 65536) { out.push(String.fromCharCode(code)); }
        else { code -= 65536; out.push(String.fromCharCode(55296 + (code >> 10), 56320 + (code & 1023))); }
        i += seq[1];
    }
    return out.join("");
}

function esUtf8TrimTail(bytes) {
    // Bytes without an incomplete UTF-8 sequence at the end (for a partial read).
    var end = bytes.length;
    for (var back = 1; back <= 3 && end - back >= 0; back++) {
        var b = bytes[end - back];
        if (b < 128) { break; }
        if (b >= 192) { return esUtf8Sequence(bytes, end - back) === null ? bytes.slice(0, end - back) : bytes; }
    }
    return bytes;
}

// ------------------------------------------------------------------ text files

function esDecodeTextFile(path, maxBytes) {
    // The decoded text of the start of a file (see the header for the encodings).
    var read = esReadBytesExact(path, maxBytes);
    var b = read.bytes;
    if (b.length >= 2 && b[0] === 255 && b[1] === 254) { return esReadUnicode(path, Math.ceil(maxBytes / 2)); }
    if (b.length >= 2 && b[0] === 254 && b[1] === 255) {
        var swapped = [];
        for (var i = 2; i + 1 < b.length; i += 2) { swapped.push(String.fromCharCode(b[i] * 256 + b[i + 1])); }
        return swapped.join("");
    }
    var bytes = esStripUtf8Bom(b);
    if (read.size > b.length) { bytes = esUtf8TrimTail(bytes); }
    var text = read.exact ? esDecodeUtf8Strict(bytes) : null;
    return text !== null ? text : esReadAnsi(path, maxBytes);
}

function esMissingPathMessage(path) {
    return "Cannot find path '" + path + "' because it does not exist.";
}

function readEsTextFile(path, maxBytes) {
    // The text of a file, capped. Never opened: a folder, a cloud placeholder, a link and a file
    // below a folder that is a link (error: getEsLinkReason, getEsRefusedFolder).
    var max = maxBytes > 0 ? maxBytes : 16384;
    var result = { path: path, text: null, size: null, truncated: false, error: null };
    var refused = getEsRefusedFolder(path);
    if (refused) { result.error = refused.reason; return result; }
    try {
        if (ES_FSO.FolderExists(path)) { result.error = "is a directory"; return result; }
        if (!ES_FSO.FileExists(path)) { result.error = esMissingPathMessage(path); return result; }
        var item = ES_FSO.GetFile(path);
        result.size = item.Size;
        if (testEsPlaceholderFile(item)) { result.error = "cloud placeholder (not downloaded)"; return result; }
        result.error = getEsLinkReason(item, path);
        if (result.error) { return result; }
        var text = esSplitLines(result.size === 0 ? "" : esDecodeTextFile(path, max * 4 + 16), 4000).join("\n");
        if (text.length > max || result.size > max) {
            result.truncated = true;
            if (text.length > max) { text = text.substr(0, max); }
        }
        result.text = text;
    } catch (e) {
        result.error = esErrorText(e);
    }
    return result;
}

// ------------------------------------------------------------------ folders

function esDirEntry(item, isFolder) {
    // A plain copy of an FSO item with the ps1 member names used by the probes.
    var entry = { Name: String(item.Name), FullName: String(item.Path), PSIsContainer: isFolder,
        Length: isFolder ? null : item.Size, Attributes: item.Attributes, LastWriteTime: null };
    try { entry.LastWriteTime = new Date(item.DateLastModified); } catch (e) { entry.LastWriteTime = null; }
    return entry;
}

function getEsDirEntries(path, max) {
    // The entries of a folder (folders first, as Get-ChildItem); none when it or a folder above
    // it is a link that is not followed.
    var limit = max > 0 ? max : 5000;
    if (getEsPathLinkReason(path)) { return []; }
    var entries = [];
    try {
        var folder = ES_FSO.GetFolder(path);
        var groups = [[folder.SubFolders, true], [folder.Files, false]];
        for (var g = 0; g < groups.length; g++) {
            var items = new Enumerator(groups[g][0]);
            for (; !items.atEnd() && entries.length < limit; items.moveNext()) { entries.push(esDirEntry(items.item(), groups[g][1])); }
        }
    } catch (e) { return []; }
    return entries;
}

function esRandomDigits() {
    return String(Math.floor(Math.random() * 1000000000)) + String(new Date().getTime() % 100000);
}

function testEsWritableDir(path) {
    // Creates and deletes one new file (never an existing one). true, false, or null when the
    // folder is missing or not an absolute local path.
    if (!testEsLocalPath(path) || !esIsDir(path)) { return null; }
    var probe = esJoinPath(path, ".envscan-write-" + esRandomDigits() + ".tmp");
    try { ES_FSO.CreateTextFile(probe, false, false).Close(); }
    catch (e) { return false; }
    try { ES_FSO.DeleteFile(probe, true); } catch (e2) { writeEsLog("cannot delete " + probe + ": " + esErrorText(e2)); }
    return true;
}

function getEsPeMachine(path) {
    // Machine type from the PE header: x86, x86_64, arm64, arm, ia64; 'script' or null otherwise.
    try {
        var bytes = readEsBytes(path, 4096);
        if (bytes.length < 64) { return null; }
        if (bytes[0] !== 77 || bytes[1] !== 90) { return bytes[0] === 35 && bytes[1] === 33 ? "script" : null; }
        var offset = bytes[60] + 256 * bytes[61] + 65536 * bytes[62];
        if (offset + 6 >= bytes.length) { return null; }
        var machine = bytes[offset + 4] + 256 * bytes[offset + 5];
        var names = { 332: "x86", 34404: "x86_64", 43620: "arm64", 452: "arm", 512: "ia64" };
        return names[machine] || ("0x" + esPadLeft(machine.toString(16), 4, "0"));
    } catch (e) { return null; }
}
