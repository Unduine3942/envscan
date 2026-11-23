// redact_xml.go: LINE RULES "xml" (redact_xml, redact_xml_pairs of redact.awk):
// <[ns:]element ...>content</ for xml_elements (start tags, content ends: redact_xmltag.go), attribute="..." for xml_attributes,
// key|name="..secret word.." value="...", <add key="<url>" value="...">.
package main

import "strings"

func (r *redactRules) redactXML(l string) string {
	if r.hasXMLElementWord(lowerASCII(l)) {
		l = r.xmlElement(l)
	}
	for _, a := range r.xmlAt {
		if strings.Contains(lowerASCII(l), a) {
			l = r.xmlAttribute(l, a)
		}
	}
	if strings.Contains(lowerASCII(l), "value") {
		l = r.redactXMLPairs(l)
	}
	return l
}

// xmlElement: <[ns:]el ...>content</ -> <[ns:]el ...><redacted></ (content: up to the element's
// own closing tag, else the next "</", empty included); with no "</" later on the line a non-blank
// rest of the line is replaced (fail closed). Self-closing tags and tags without ">" stay.
func (r *redactRules) xmlElement(l string) string {
	x := r.newXMLLine(lowerASCII(l))
	var out strings.Builder
	p, from := 0, 0
	for {
		tg, ok := x.next(from)
		if !ok {
			break
		}
		from = tg.start + 1
		if tg.gt < 0 {
			continue
		}
		if tg.close < 0 {
			if !isAllWS(l[tg.gt+1:]) {
				out.WriteString(l[p:tg.gt+1] + r.ph)
				p = len(l)
			}
			break
		}
		out.WriteString(l[p:tg.gt+1] + r.ph)
		p, from = tg.close, tg.close
	}
	out.WriteString(l[p:])
	return out.String()
}

// xmlAttribute: a="..." -> a="<redacted>" (the attribute name not after a word character)
func (r *redactRules) xmlAttribute(l, a string) string {
	name, dq := newFinder(lowerASCII(l), a), newFinder(l, `"`)
	var out strings.Builder
	p := 0
	for {
		k := name.next(p)
		if k < 0 {
			break
		}
		if k == p || !isWordByte(l[k-1]) {
			if j := quotedAfterEquals(l, k+len(a)); j >= 0 {
				if e := dq.next(j + 1); e >= 0 {
					out.WriteString(l[p:j+1] + r.ph)
					p = e
					continue
				}
			}
		}
		out.WriteString(l[p : k+len(a)])
		p = k + len(a)
	}
	out.WriteString(l[p:])
	return out.String()
}

// quotedAfterEquals: [ws] = [ws] " at s[j:]: the index of the opening quote, else -1
func quotedAfterEquals(s string, j int) int {
	j = skipWS(s, j)
	if at(s, j) != '=' {
		return -1
	}
	j = skipWS(s, j+1)
	if at(s, j) != '"' {
		return -1
	}
	return j
}

// redactXMLPairs: key="..secret word.." value="..." and name="..secret word.." value="...",
// and <add key="<url>" value="..."> (NuGet apikeys)
func (r *redactRules) redactXMLPairs(l string) string {
	lo := lowerASCII(l)
	fk, fn, dq := newFinder(lo, "key"), newFinder(lo, "name"), newFinder(l, `"`)
	var out strings.Builder
	p := 0
	for {
		k1, k2 := fk.next(p), fn.next(p)
		if k1 < 0 && k2 < 0 {
			break
		}
		k, w := k2, 4
		if k1 >= 0 && (k2 < 0 || k1 < k2) {
			k, w = k1, 3
		}
		if k == p || !isWordByte(l[k-1]) {
			if ve := r.xmlPairValue(&out, l, lo, dq, p, k, w); ve >= 0 {
				p = ve
				continue
			}
		}
		out.WriteString(l[p : k+w])
		p = k + w
	}
	out.WriteString(l[p:])
	return out.String()
}

// xmlPairValue: key|name="v" at l[k:]: when v holds a secret word (or is a URL key of <add>) and
// value="..." follows, writes through the opening quote of the value and the placeholder and
// returns the index of its closing quote, else -1
func (r *redactRules) xmlPairValue(out *strings.Builder, l, lo string, dq *finder, p, k, w int) int {
	j := quotedAfterEquals(l, k+w)
	if j < 0 {
		return -1
	}
	e := dq.next(j + 1)
	if e < 0 {
		return -1
	}
	lval := lo[j+1 : e]
	hit := containsAny(lval, r.xmlWords)
	if !hit && w == 3 && isURLStart(lval) && addBefore(out.String(), l[p:k]) {
		hit = true
	}
	if !hit || !isWS(at(l, e+1)) {
		return -1
	}
	j = skipWS(l, e+1)
	if lowerASCII(window(l, j, 5)) != "value" {
		return -1
	}
	j = quotedAfterEquals(l, j+5)
	if j < 0 {
		return -1
	}
	ve := dq.next(j + 1)
	if ve < 0 {
		return -1
	}
	out.WriteString(l[p:j+1] + r.ph)
	return ve
}

// isURLStart: ^[a-z][a-z0-9+.-]*://
func isURLStart(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	j := 1
	for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || isDigit(s[j]) || s[j] == '+' || s[j] == '.' || s[j] == '-') {
		j++
	}
	return strings.HasPrefix(s[j:], "://")
}

// addBefore: done + mid ends with "<add" and blanks (any case)
func addBefore(done, mid string) bool {
	t := strings.TrimRight(mid, " \t")
	blanks := len(mid) - len(t)
	if t == "" {
		o := strings.TrimRight(done, " \t")
		blanks += len(done) - len(o)
		t = o
	} else if len(t) < 4 {
		t = done[max(0, len(done)-4):] + t
	}
	return blanks > 0 && strings.HasSuffix(lowerASCII(t[max(0, len(t)-4):]), "<add")
}
