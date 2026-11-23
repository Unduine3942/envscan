// ---------------------------------------------------------------------------
// 22-probes-certder: the subject, issuer and expiry of a certificate kept in the
// registry certificate stores (SystemCertificates\<store>\Certificates\<thumbprint>
// "Blob"), read without CryptoAPI: the Blob is a list of fields (id, flags and
// length as 32-bit little-endian numbers, then the data); property 32 is the DER
// certificate. Names are formatted like .NET X509Certificate.Subject (reversed RDNs,
// ", " between them, values with special characters quoted).
// ---------------------------------------------------------------------------

var JSDER_CERT_PROP_ID = 32;
var JSDER_ATTR_NAMES = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S",
    "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T", "2.5.4.42": "G", "2.5.4.43": "I",
    "2.5.4.17": "PostalCode", "2.5.4.13": "Description", "2.5.4.46": "dnQualifier",
    "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "E"
};

function jsDer_uint32(bytes, pos) {
    return bytes[pos] + bytes[pos + 1] * 256 + bytes[pos + 2] * 65536 + bytes[pos + 3] * 16777216;
}

function jsDer_certFromBlob(bytes) {
    // The DER certificate (property 32) of a serialized store element, else null.
    var pos = 0;
    while (pos + 12 <= bytes.length) {
        var id = jsDer_uint32(bytes, pos);
        var length = jsDer_uint32(bytes, pos + 8);
        var start = pos + 12;
        if (start + length > bytes.length) { return null; }
        if (id === JSDER_CERT_PROP_ID) { return bytes.slice(start, start + length); }
        pos = start + length;
    }
    return null;
}

function jsDer_node(bytes, pos, limit) {
    // One TLV at pos: { tag, start (content), end } within limit, else null.
    if (pos + 2 > limit) { return null; }
    var first = bytes[pos + 1];
    var start = pos + 2;
    var length = first;
    if (first >= 0x80) {
        var count = first & 0x7f;
        if (count < 1 || count > 3 || start + count > limit) { return null; }
        length = 0;
        for (var i = 0; i < count; i++) { length = length * 256 + bytes[start + i]; }
        start += count;
    }
    if (start + length > limit) { return null; }
    return { tag: bytes[pos], start: start, end: start + length };
}

function jsDer_children(bytes, node) {
    var out = [];
    var pos = node.start;
    while (pos < node.end) {
        var child = jsDer_node(bytes, pos, node.end);
        if (!child) { return null; }
        out.push(child);
        pos = child.end;
    }
    return out;
}

function jsDer_oid(bytes, node) {
    if (node.end <= node.start) { return ""; }
    var first = bytes[node.start];
    var parts = first >= 80 ? [2, first - 80] : [Math.floor(first / 40), first % 40];
    var value = 0;
    for (var i = node.start + 1; i < node.end; i++) {
        value = value * 128 + (bytes[i] & 0x7f);
        if ((bytes[i] & 0x80) === 0) { parts.push(value); value = 0; }
    }
    return parts.join(".");
}

function jsDer_utf8(bytes, start, end) {
    var out = "";
    var i = start;
    while (i < end) {
        var b = bytes[i];
        var extra = b >= 0xf0 ? 3 : (b >= 0xe0 ? 2 : (b >= 0xc0 ? 1 : 0));
        var code = extra === 0 ? b : (b & (0x3f >> extra));
        for (var k = 1; k <= extra && i + k < end; k++) { code = code * 64 + (bytes[i + k] & 0x3f); }
        i += extra + 1;
        if (code > 0xffff) {
            code -= 0x10000;
            out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
        } else { out += String.fromCharCode(code); }
    }
    return out;
}

function jsDer_text(bytes, node) {
    // A directory string: UTF8String, BMPString, UniversalString or a single-byte string type.
    var out = "";
    var i;
    if (node.tag === 0x0c) { return jsDer_utf8(bytes, node.start, node.end); }
    if (node.tag === 0x1e) {
        for (i = node.start; i + 1 < node.end; i += 2) { out += String.fromCharCode(bytes[i] * 256 + bytes[i + 1]); }
        return out;
    }
    if (node.tag === 0x1c) {
        for (i = node.start; i + 3 < node.end; i += 4) { out += String.fromCharCode(bytes[i + 2] * 256 + bytes[i + 3]); }
        return out;
    }
    for (i = node.start; i < node.end; i++) { out += String.fromCharCode(bytes[i]); }
    return out;
}

function jsDer_quote(value) {
    // CertNameToStr quoting: special characters, leading or trailing spaces, or an empty value.
    if (value === "" || /[,+="\r\n<>#;]/.test(value) || /^\s|\s$/.test(value)) {
        return "\"" + value.replace(/"/g, "\"\"") + "\"";
    }
    return value;
}

function jsDer_rdn(bytes, set) {
    // "KEY=value" for each attribute of one relative distinguished name (joined by " + ").
    var pairs = jsDer_children(bytes, set);
    if (!pairs) { return null; }
    var out = [];
    for (var i = 0; i < pairs.length; i++) {
        var parts = jsDer_children(bytes, pairs[i]);
        if (!parts || parts.length < 2 || parts[0].tag !== 0x06) { return null; }
        var oid = jsDer_oid(bytes, parts[0]);
        var key = esHas(JSDER_ATTR_NAMES, oid) ? JSDER_ATTR_NAMES[oid] : "OID." + oid;
        out.push(key + "=" + jsDer_quote(jsDer_text(bytes, parts[1])));
    }
    return out.join(" + ");
}

function jsDer_name(bytes, node) {
    // Distinguished name, most specific RDN first (.NET order), else null.
    var sets = jsDer_children(bytes, node);
    if (!sets) { return null; }
    var out = [];
    for (var i = sets.length - 1; i >= 0; i--) {
        var rdn = jsDer_rdn(bytes, sets[i]);
        if (rdn === null) { return null; }
        out.push(rdn);
    }
    return out.join(", ");
}

function jsDer_time(bytes, node) {
    // UTCTime (YYMMDDHHMMSSZ, 1950-2049) or GeneralizedTime (YYYYMMDDHHMMSSZ) as a Date.
    var text = jsDer_text(bytes, node);
    var m = node.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(text)
        : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?Z$/.exec(text);
    if (!m) { return null; }
    var year = parseInt(m[1], 10);
    if (node.tag === 0x17) { year += year < 50 ? 2000 : 1900; }
    return new Date(Date.UTC(year, parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), m[6] ? parseInt(m[6], 10) : 0));
}

function jsDer_tbsParts(cert) {
    // [serial, signature, issuer, validity, subject] of the TBSCertificate, else null.
    var top = jsDer_node(cert, 0, cert.length);
    var outer = top ? jsDer_children(cert, top) : null;
    if (!outer || outer.length < 1 || outer[0].tag !== 0x30) { return null; }
    var parts = jsDer_children(cert, outer[0]);
    if (!parts) { return null; }
    if (parts.length > 0 && parts[0].tag === 0xa0) { parts = parts.slice(1); }
    if (parts.length < 5 || parts[2].tag !== 0x30 || parts[3].tag !== 0x30 || parts[4].tag !== 0x30) { return null; }
    return parts;
}

function jsDer_parseCert(cert) {
    // { subject, issuer, not_after (Date) } of a DER certificate, else null.
    var parts = jsDer_tbsParts(cert);
    if (!parts) { return null; }
    var validity = jsDer_children(cert, parts[3]);
    var subject = jsDer_name(cert, parts[4]);
    var issuer = jsDer_name(cert, parts[2]);
    if (!validity || validity.length < 2 || subject === null || issuer === null) { return null; }
    return { subject: subject, issuer: issuer, not_after: jsDer_time(cert, validity[1]) };
}

function jsDer_parseBlob(bytes) {
    // Subject, issuer and expiry of a registry certificate Blob (array of byte values), else null.
    if (!bytes || bytes.length < 12) { return null; }
    try {
        var cert = jsDer_certFromBlob(bytes);
        return cert ? jsDer_parseCert(cert) : null;
    } catch (e) { return null; }
}

function jsDer_hexBytes(hex) {
    // Byte values of a hexadecimal string (the engine's REG_BINARY text form).
    var text = jsOs_str(hex);
    var out = [];
    for (var i = 0; i + 1 < text.length; i += 2) { out.push(parseInt(text.substr(i, 2), 16)); }
    return out;
}
