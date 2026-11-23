// redact_text.go: TEXT RULES (block_open, triple_open, xml_open, until_line, text_line of
// redact.awk) for whole configuration files and raw output.
package main

import (
	"regexp"
	"strings"
)

// blockTailRe: what follows a key that opens a block: (= or :) then nothing, "{", "[" or a YAML
// block scalar (| |- > >- |2 ...)
var blockTailRe = regexp.MustCompile(`^["']?[ \t]*[:=][ \t]*([\[{]|[|>][-+0-9]*)?[ \t]*$`)

// textState: the open block's indent (-1: none) and the delimiter closing an open multi-line
// value ("": none)
type textState struct {
	block int
	until string
	// a secret start tag whose ">" is not on its line: its closing delimiter and the quote state
	// at the end of the last line (redact_xmltext.go)
	tagUntil string
	tagQuote int
}

// text: a whole file or raw output, line by line: a private key anywhere replaces the whole
// text. The line structure stays (a "\r" before a "\n" is dropped, a last line break is kept);
// the byte cap and the "[... truncated]" marker of sh read_file are the caller's.
func (r *redactRules) text(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, r.pkMarker) {
		return redactPKText
	}
	st := &textState{block: -1}
	ls := strings.Split(s, "\n")
	for i := 0; i < len(ls)-1; i++ {
		ls[i] = strings.TrimSuffix(ls[i], "\r")
	}
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = r.textLine(l, st)
	}
	return strings.Join(out, "\n")
}

func (r *redactRules) textLine(line string, st *textState) string {
	if st.until != "" {
		return r.untilLine(line, st)
	}
	if st.tagUntil != "" {
		return r.startTagLine(line, st)
	}
	ni := leadingBlank(line)
	if st.block >= 0 {
		t := line[ni:]
		if t == "" || isClosingOnly(t) {
			return line
		}
		if ni > st.block || (ni == st.block && strings.HasPrefix(t, "- ")) {
			return line[:ni] + r.ph
		}
		st.block = -1
	}
	out := r.line(line)
	hasSep := strings.ContainsAny(line, ":=")
	if ind, ok := r.blockOpen(line); hasSep && ok {
		st.block = ind
	} else if d, ok := r.tripleOpen(line); hasSep && ok {
		st.until = d
	} else if strings.IndexByte(line, '<') >= 0 {
		r.xmlOpen(line, st)
	}
	return out
}

// isClosingOnly: ^[}\]]+[,;]?[ \t]*$
func isClosingOnly(t string) bool {
	j := 0
	for j < len(t) && (t[j] == '}' || t[j] == ']') {
		j++
	}
	if j == 0 {
		return false
	}
	if c := at(t, j); c == ',' || c == ';' {
		j++
	}
	return strings.TrimLeft(t[j:], " \t") == ""
}

// lineKeyRun: the start and end of the [quoted] key after [indent] (and "- " when dash)
func lineKeyRun(line string, dash bool) (int, int) {
	p := leadingBlank(line)
	if dash {
		p = keyStart(line)
	}
	if isQuote(at(line, p)) {
		p++
	}
	ks := p
	for p < len(line) && isLineKeyByte(line[p]) {
		p++
	}
	return ks, p
}

// blockOpen: [indent] [- ] [quote] key [quote] (= or :) [ "{" | "[" | block scalar ] with a
// secret key; the indent of the line
func (r *redactRules) blockOpen(line string) (int, bool) {
	ks, ke := lineKeyRun(line, true)
	for n := ke - ks; n > 0; n-- {
		if blockTailRe.MatchString(line[ks+n:]) {
			return leadingBlank(line), r.secretName(line[ks : ks+n])
		}
	}
	return 0, false
}

// tripleOpen: [indent] [quote] key [quote] (= or :) """ (or three single quotes) not closed on the line, with a
// secret key; the delimiter
func (r *redactRules) tripleOpen(line string) (string, bool) {
	ks, ke := lineKeyRun(line, false)
	for n := ke - ks; n > 0; n-- {
		after := line[ks+n:]
		m := sepLenLoose(after)
		if m < 0 {
			continue
		}
		d := window(after, m, 3)
		if (d != `"""` && d != `'''`) || strings.Contains(after[m+3:], d) {
			continue
		}
		if !r.secretName(line[ks : ks+n]) {
			return "", false
		}
		return d, true
	}
	return "", false
}

// sepLenLoose: the length of ["']? [blanks] (: or =) [blanks] at the start of s, -1 when none
func sepLenLoose(s string) int {
	j := 0
	if isQuote(at(s, 0)) {
		j++
	}
	j = skipBlank(s, j)
	if c := at(s, j); j >= len(s) || (c != ':' && c != '=') {
		return -1
	}
	return skipBlank(s, j+1)
}

// isAllWS: s holds only whitespace
func isAllWS(s string) bool { return skipWS(s, 0) == len(s) }
