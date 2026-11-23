// redact_xmltext.go: the xml part of TEXT RULES "multi-line" (spec/redaction.toml): a secret
// element left open on its line, its following lines up to the closing tag, a rescan of what
// follows that tag, and start tags whose ">" is on a later line (the start-tag state).
package main

import "strings"

// xmlOpen: the state a line leaves open. Only the first start tag with no "</" after it decides:
// it opens the multi-line state when the rest of the line after it is blank or the tag is the
// first thing on the line. A start tag without its ">" on the line opens the start-tag state.
func (r *redactRules) xmlOpen(line string, st *textState) {
	lo := lowerASCII(line)
	if !r.hasXMLElementWord(lo) {
		return
	}
	x, first := r.newXMLLine(lo), leadingBlank(line)
	for from := 0; ; {
		tg, ok := x.next(from)
		if !ok {
			return
		}
		if tg.gt < 0 {
			st.tagUntil, st.tagQuote = tg.until, tg.eol
			return
		}
		if tg.close < 0 {
			if tg.start == first || isAllWS(lo[tg.gt+1:]) {
				st.until = tg.until
			}
			return
		}
		from = tg.close
	}
}

// untilLine: a line inside a multi-line value: replaced up to the closing delimiter, which ends
// the value and stays. After an xml closing tag the rest of the line goes through the line and
// text rules again.
func (r *redactRules) untilLine(line string, st *textState) string {
	ni := leadingBlank(line)
	until := st.until
	k := r.untilIndex(line, until)
	if k < 0 {
		if strings.Trim(line, " \t\r") == "" {
			return line
		}
		return line[:ni] + r.ph
	}
	st.until = ""
	b := line[:k]
	if strings.Trim(b, " \t\r") != "" {
		b = line[:ni] + r.ph
	}
	if !strings.HasPrefix(until, "</") {
		return b + line[k:]
	}
	return b + r.textLine(line[k:], st)
}

// untilIndex: where the delimiter closing a multi-line value starts (xml: outside comments)
func (r *redactRules) untilIndex(line, until string) int {
	lo := lowerASCII(line)
	if !strings.HasPrefix(until, "</") {
		return strings.Index(lo, until)
	}
	return firstFrom(r.newXMLLine(lo).closeKeys()[until], 0)
}

// startTagLine: a line after a secret start tag that had no ">" on its line. A line starting with
// "<" ends the state without effect; a line without the tag's ">" (outside quotes) gets the line
// rules; on the line with it, what follows the ">" is content right after a start tag.
func (r *redactRules) startTagLine(line string, st *textState) string {
	until := st.tagUntil
	if at(line, leadingBlank(line)) == '<' {
		st.tagUntil = ""
		return r.textLine(line, st)
	}
	x := r.newXMLLine(lowerASCII(line))
	g, q := x.tagEnd(0, st.tagQuote)
	if g < 0 {
		st.tagQuote = q
		return r.line(line)
	}
	st.tagUntil = ""
	if g > 0 && line[g-1] == '/' {
		return r.line(line[:g+1]) + r.textLine(line[g+1:], st)
	}
	head, tail := r.line(line[:g+1]), line[g+1:]
	if k := x.contentEnd(g+1, until); k >= 0 {
		return head + r.ph + r.textLine(line[k:], st)
	}
	st.until = until
	if isAllWS(tail) {
		return head + tail
	}
	return head + r.ph
}
