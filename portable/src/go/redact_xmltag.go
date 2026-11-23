// redact_xmltag.go: the start tags of secret xml elements and where their content ends (spec/
// redaction.toml LINE RULES "xml"): "<", an optional namespace prefix ([A-Za-z_][A-Za-z0-9_.-]*
// ":", only when an element name follows it), an xml_elements name (any case, not followed by a
// word character), attributes, then the first ">" outside "..." and '...' (self-closing only with
// "/" right before it). The content ends at the element's own closing tag "</[prefix:]element",
// else at the next "</"; closing tags inside <!-- ... --> do not count. Linear time: the tag ends
// come from one backward pass over the line, the closing tags from one forward pass.
package main

import (
	"sort"
	"strings"
)

// quote states of the start-tag scan (also carried across lines in TEXT mode)
const (
	qNone = iota
	qDouble
	qSingle
)

// xmlTag: a secret start tag at start, its ">" at gt (-1: none on the line; eol is then the quote
// state at the end of the line), where its content ends at close (-1: no "</" after it) and the
// delimiter that closes the element, "</" [prefix ":"] element (lower case).
type xmlTag struct {
	start, gt, close, eol int
	until                 string
}

// xmlLine: one lower-cased line with its tag-end table (built on first use) and its closing tags
// outside comments.
type xmlLine struct {
	lo     string
	els    []string
	lt     *finder
	ends   [3][]int32
	closes []int
	keyed  map[string][]int
}

func (r *redactRules) newXMLLine(lo string) *xmlLine {
	return &xmlLine{lo: lo, els: r.xmlEl, lt: newFinder(lo, "<"), closes: xmlCloses(lo)}
}

// xmlCloses: the positions of "</" outside XML comments (comments read from the line start; an
// unterminated "<!--" hides the rest of the line)
func xmlCloses(lo string) []int {
	var out []int
	cl, co, ce := newFinder(lo, "</"), newFinder(lo, "<!--"), newFinder(lo, "-->")
	for p := 0; ; {
		k := cl.next(p)
		if k < 0 {
			return out
		}
		if c := co.next(p); c >= 0 && c < k {
			e := ce.next(c + 4)
			if e < 0 {
				return out
			}
			p = e + 3
			continue
		}
		out = append(out, k)
		p = k + 2
	}
}

// next: the first secret start tag at or after from that is not self-closing (incomplete tags,
// gt -1, included).
func (x *xmlLine) next(from int) (xmlTag, bool) {
	for {
		i := x.lt.next(from)
		if i < 0 {
			return xmlTag{}, false
		}
		from = i + 1
		j, until := x.name(i)
		if j < 0 {
			continue
		}
		g, q := x.tagEnd(j, qNone)
		if g < 0 {
			return xmlTag{start: i, gt: -1, close: -1, eol: q, until: until}, true
		}
		if x.lo[g-1] == '/' {
			continue
		}
		return xmlTag{start: i, gt: g, close: x.contentEnd(g+1, until), until: until}, true
	}
}

// name: after the "<" at i, an optional prefix and a secret element name; the index after the
// name and the closing delimiter, else -1. The prefix counts only when an element follows it.
func (x *xmlLine) name(i int) (int, string) {
	j := i + 1
	if n := prefixRun(x.lo[j:]); n > 0 && at(x.lo, j+n) == ':' {
		if e := x.elementEnd(j + n + 1); e >= 0 {
			return e, "</" + x.lo[j:e]
		}
	}
	if e := x.elementEnd(j); e >= 0 {
		return e, "</" + x.lo[j:e]
	}
	return -1, ""
}

func (x *xmlLine) elementEnd(j int) int {
	for _, el := range x.els {
		if el != "" && strings.HasPrefix(x.lo[j:], el) && !isWordByte(at(x.lo, j+len(el))) {
			return j + len(el)
		}
	}
	return -1
}

// prefixRun: the length of [a-z_][a-z0-9_.-]* at the start of s
func prefixRun(s string) int {
	if c := at(s, 0); !((c >= 'a' && c <= 'z') || c == '_') {
		return 0
	}
	n := 1
	for n < len(s) && isKeyByte(s[n]) {
		n++
	}
	return n
}

// tagEnd: the tag-ending ">" at or after j for a scan that starts in quote state q; else -1 and
// the quote state at the end of the line.
func (x *xmlLine) tagEnd(j, q int) (int, int) {
	if x.ends[qNone] == nil {
		x.buildEnds()
	}
	v := x.ends[q][j]
	if v >= 0 {
		return int(v), qNone
	}
	return -1, int(-v - 1)
}

// buildEnds: ends[q][i] = the first ">" outside quotes from i in state q, else -1-(state at the end)
func (x *xmlLine) buildEnds() {
	n := len(x.lo)
	for q := range x.ends {
		x.ends[q] = make([]int32, n+1)
		x.ends[q][n] = int32(-1 - q)
	}
	none, dq, sq := x.ends[qNone], x.ends[qDouble], x.ends[qSingle]
	for i := n - 1; i >= 0; i-- {
		none[i], dq[i], sq[i] = none[i+1], dq[i+1], sq[i+1]
		switch x.lo[i] {
		case '>':
			none[i] = int32(i)
		case '"':
			none[i], dq[i] = dq[i+1], none[i+1]
		case '\'':
			none[i], sq[i] = sq[i+1], none[i+1]
		}
	}
}

// contentEnd: the element's own closing tag at or after from, else the next "</" (both outside
// comments), else -1
func (x *xmlLine) contentEnd(from int, until string) int {
	if k := firstFrom(x.closeKeys()[until], from); k >= 0 {
		return k
	}
	return firstFrom(x.closes, from)
}

// closeKeys: the closing tags by their "</[prefix:]element" keys (a tag can carry two:
// "</password:token" closes both "</password" and "</password:token")
func (x *xmlLine) closeKeys() map[string][]int {
	if x.keyed != nil {
		return x.keyed
	}
	x.keyed = map[string][]int{}
	for _, k := range x.closes {
		rest := x.lo[k+2:]
		for _, el := range x.els {
			if el != "" && strings.HasPrefix(rest, el) {
				x.keyed["</"+el] = append(x.keyed["</"+el], k)
			}
		}
		n := prefixRun(rest)
		if n == 0 || at(rest, n) != ':' {
			continue
		}
		for _, el := range x.els {
			if el != "" && strings.HasPrefix(rest[n+1:], el) {
				key := "</" + rest[:n+1] + el
				x.keyed[key] = append(x.keyed[key], k)
			}
		}
	}
	return x.keyed
}

// firstFrom: the first of the sorted positions ps at or after from, -1 when none
func firstFrom(ps []int, from int) int {
	if i := sort.SearchInts(ps, from); i < len(ps) {
		return ps[i]
	}
	return -1
}

// hasXMLElementWord: the lower-cased line may hold a secret start tag (cheap pre-check).
func (r *redactRules) hasXMLElementWord(lo string) bool {
	return strings.IndexByte(lo, '<') >= 0 && containsAny(lo, r.xmlEl)
}
