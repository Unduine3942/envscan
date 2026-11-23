// redact_line.go: LINE RULES (line_key, redact_spacepairs, redact_line of redact.awk); the xml
// rules are in redact_xml.go.
package main

import "strings"

func (r *redactRules) line(line string) string {
	if line == "" {
		return line
	}
	if len(line) > redactMaxLen {
		return redactTooLong
	}
	l := line
	if strings.ContainsAny(l, `"'`) {
		l = r.redactSpacePairs(l)
	}
	if !strings.ContainsAny(l, "=:<") {
		return r.value(l)
	}
	// bare userinfo first: in "svc:pw@proxy.corp:8080" the line-key rule would see a key
	if strings.IndexByte(l, '@') > 0 && strings.IndexByte(l, ':') >= 0 {
		l = r.redactUserinfo(l)
	}
	key, head, ok := lineKey(l, true)
	if !ok {
		key, head, ok = lineKey(l, false)
	}
	if ok && r.secretName(key) {
		l = head + r.ph
	}
	if strings.IndexByte(l, '<') >= 0 {
		l = r.redactXML(l)
	}
	return r.value(l)
}

// keyStart: the position after [indent] [- ] (block and line keys)
func keyStart(line string) int {
	p := leadingBlank(line)
	if at(line, p) == '-' {
		if q := skipBlank(line, p+1); q > p+1 {
			p = q
		}
	}
	return p
}

// sepLen: the length of ["']? [ \t]* (: or =) [ \t]* at the start of s, 0 when there is none
func sepLen(s string) int {
	j := 0
	if isQuote(at(s, 0)) {
		j++
	}
	j = skipBlank(s, j)
	if c := at(s, j); j >= len(s) || (c != ':' && c != '=') {
		return 0
	}
	return skipBlank(s, j+1)
}

// lineKey: [indent] [- ] [export |set ] [quote] key [quote] (= or :) <rest>; the key and the
// line through the separator. A rest of only "{" or "[" is no match.
func lineKey(line string, skipKW bool) (key, head string, ok bool) {
	p := keyStart(line)
	if skipKW {
		lo := lowerASCII(window(line, p, 7))
		switch {
		case strings.HasPrefix(lo, "export") && len(lo) > 6 && (lo[6] == ' ' || lo[6] == '\t'):
			p += 6
		case strings.HasPrefix(lo, "set") && len(lo) > 3 && (lo[3] == ' ' || lo[3] == '\t'):
			p += 3
		default:
			return "", "", false
		}
		p = skipBlank(line, p)
	}
	if isQuote(at(line, p)) {
		p++
	}
	ks := p
	for p < len(line) && isLineKeyByte(line[p]) {
		p++
	}
	for n := p - ks; n > 0; n-- {
		after := line[ks+n:]
		m := sepLen(after)
		if m == 0 || m >= len(after) {
			continue
		}
		if isBracketOnly(after[m:]) {
			return "", "", false
		}
		return line[ks : ks+n], line[:ks+n+m], true
	}
	return "", "", false
}

// isBracketOnly: "{" or "[" and blanks
func isBracketOnly(s string) bool {
	c := at(s, 0)
	return (c == '{' || c == '[') && strings.TrimLeft(s[1:], " \t") == ""
}

// redactSpacePairs: <secret key> <whitespace> <quoted value> (Groovy password "x", yarn classic
// "//reg/:_authToken" "x"); the key starts the text or follows whitespace, { ( ; or ","
func (r *redactRules) redactSpacePairs(l string) string {
	var out strings.Builder
	i := 0
	for i < len(l) {
		if i == 0 || isWS(l[i-1]) || strings.IndexByte("{(;,", l[i-1]) >= 0 {
			if next, ok := r.spacePairAt(&out, l, i); ok {
				i = next
				continue
			}
		}
		out.WriteByte(l[i])
		i++
	}
	return out.String()
}

// spacePairAt: a [quoted] key at l[i], blanks and a quoted value: writes it (the value replaced
// when the key is a secret name) and returns the position after the value
func (r *redactRules) spacePairAt(out *strings.Builder, l string, i int) (int, bool) {
	k := i
	var q byte
	if isQuote(l[i]) {
		q = l[i]
		k++
	}
	ks := k
	for k < len(l) && isLineKeyByte(l[k]) {
		k++
	}
	ke := k
	if ke == ks || (q != 0 && at(l, k) != q) {
		return 0, false
	}
	if q != 0 {
		k++
	}
	w := k
	k = skipBlank(l, k)
	c := at(l, k)
	if k == w || !isQuote(c) {
		return 0, false
	}
	ve := spQuoteEnd(l, k, c)
	if ve < 0 {
		return 0, false
	}
	if r.secretName(l[ks:ke]) {
		out.WriteString(l[i:k+1] + r.ph + string(c))
	} else {
		out.WriteString(l[i : ve+1])
	}
	return ve + 1, true
}

// spQuoteEnd: the quote closing the one at s[k] ("..." with backslash escapes, '...' without),
// -1 when none
func spQuoteEnd(s string, k int, q byte) int {
	for k++; k < len(s); {
		if q == '"' && s[k] == '\\' {
			k += 2
			continue
		}
		if s[k] == q {
			return k
		}
		k++
	}
	return -1
}
