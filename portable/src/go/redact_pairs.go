// redact_pairs.go: VALUE RULES "pair keys", "key/value" and "unquoted run" (redact_pairkeys,
// redact_pairs, run_end, placeholder_end of redact.awk).
package main

import (
	"regexp"
	"strings"
)

// pairRe: key[quote][space](= or :)[space], the quote possibly escaped (awk redact_pairs)
var pairRe = regexp.MustCompile(`[A-Za-z0-9_.-]+(\\?["'])?[ \t\r\n]*[:=][ \t\r\n]*`)

func init() { pairRe.Longest() }

func isRunSep(c byte) bool { return strings.IndexByte(runSeparators, c) >= 0 }

// keyAhead: s[k:] starts another key: [A-Za-z0-9_.-]+ ["']? [whitespace]* (= or :)
func keyAhead(s string, k int) bool {
	j := k
	for j < len(s) && isKeyByte(s[j]) {
		j++
	}
	if j == k {
		return false
	}
	if isQuote(at(s, j)) {
		j++
	}
	j = skipWS(s, j)
	c := at(s, j)
	return j < len(s) && (c == '=' || c == ':')
}

// runEnd: the end of an unquoted value from j (spec "unquoted run")
func runEnd(s string, j int) int {
	for j < len(s) {
		c := s[j]
		if isWS(c) {
			break
		}
		if isRunSep(c) {
			k := j
			for k < len(s) && isRunSep(s[k]) {
				k++
			}
			if k >= len(s) || isWS(s[k]) || keyAhead(s, k) {
				break
			}
			j = k
			continue
		}
		j++
	}
	return j
}

// placeholderEnd: s[j:] starts with the placeholder; the end of the value that continues it
func (r *redactRules) placeholderEnd(s string, j int) int { return runEnd(s, j+len(r.ph)) }

// pairKeyAt: the earliest pair key at or after p (the longer one on a tie), -1 when none
func (r *redactRules) pairKeyAt(fs []*finder, p int) (int, int) {
	best, bk := -1, -1
	for i, f := range fs {
		k := f.next(p)
		if k < 0 {
			continue
		}
		if best < 0 || k < best || (k == best && len(r.pairKeys[i]) > len(r.pairKeys[bk])) {
			best, bk = k, i
		}
	}
	return best, bk
}

// redactPairKeys: <key>=<value> for the pair_keys, anywhere, key not after a key character
func (r *redactRules) redactPairKeys(v string) string {
	lv := lowerASCII(v)
	fs := make([]*finder, len(r.pairKeys))
	for i, k := range r.pairKeys {
		fs[i] = newFinder(lv, k)
	}
	var out strings.Builder
	p := 0
	for {
		k, bk := r.pairKeyAt(fs, p)
		if k < 0 {
			break
		}
		if k == p || !isKeyByte(v[k-1]) {
			if pre, e := r.pairKeyValue(v, k+len(r.pairKeys[bk])); e > 0 {
				out.WriteString(v[p:pre] + r.ph)
				p = e
				continue
			}
		}
		out.WriteString(v[p : k+1])
		p = k + 1
	}
	out.WriteString(v[p:])
	return out.String()
}

// pairKeyValue: j is after a pair key; when "=" and a value follow: the end of the text kept
// before the placeholder and the end of the value (0: no value)
func (r *redactRules) pairKeyValue(v string, j int) (int, int) {
	j = skipWS(v, j)
	if at(v, j) != '=' {
		return 0, 0
	}
	j = skipWS(v, j+1)
	pre := j
	switch {
	case strings.HasPrefix(from(v, j), r.ph):
		if e := r.placeholderEnd(v, j); e != j+len(r.ph) {
			return pre, e
		}
		return 0, 0
	case escQuote(v, j):
		if e := escEnd(v, j); e >= 0 {
			return j + 2, e
		}
		return j + 2, len(v)
	case isQuote(at(v, j)):
		if e := quoteEnd(v, j); e >= 0 {
			return pre, e + 1
		}
		return pre, len(v)
	}
	if e := runEnd(v, j); e > j {
		return pre, e
	}
	return 0, 0
}

// redactPairs: every key[quote][space](= or :)[space]value whose key is a secret name (keys
// ending in AUTHORIZATION are left to redactAuthz)
func (r *redactRules) redactPairs(v string) string {
	var out strings.Builder
	p := 0
	for p < len(v) {
		m := pairRe.FindStringIndex(v[p:])
		if m == nil {
			break
		}
		k, j := p+m[0], p+m[1]
		ke := k
		for ke < j && isKeyByte(v[ke]) {
			ke++
		}
		key := v[k:ke]
		if j >= len(v) || r.xmlQName(v, k, ke, j) || strings.HasSuffix(upperASCII(key), "AUTHORIZATION") || !r.secretName(key) {
			out.WriteString(v[p:j])
			p = j
			continue
		}
		next, done := r.pairValue(&out, v, p, j)
		if done {
			return out.String()
		}
		p = next
	}
	out.WriteString(v[p:])
	return out.String()
}

// xmlQName: the key at v[k:ke] is the prefix of an XML name, "<a:element" or "</a:element" (":"
// right after the key, then an xml_elements name, any case, not followed by a word character), not
// a key: <token:password> stays for the xml rules. "<password:x>" stays a key/value pair.
func (r *redactRules) xmlQName(v string, k, ke, j int) bool {
	if j != ke+1 || v[ke] != ':' {
		return false
	}
	if at(v, k-1) != '<' && (at(v, k-1) != '/' || at(v, k-2) != '<') {
		return false
	}
	lo := lowerASCII(window(v, j, 64))
	for _, el := range r.xmlEl {
		if el != "" && strings.HasPrefix(lo, el) && !isWordByte(at(lo, len(el))) {
			return true
		}
	}
	return false
}

// pairValue: the value of a secret key at v[j:]; writes v[p:...] and the placeholder, returns
// where the text goes on (done: the value ran to the end of the text)
func (r *redactRules) pairValue(out *strings.Builder, v string, p, j int) (int, bool) {
	if strings.HasPrefix(v[j:], r.ph) {
		e := r.placeholderEnd(v, j)
		if e == j+len(r.ph) {
			out.WriteString(v[p:e])
		} else {
			out.WriteString(v[p:j] + r.ph)
		}
		return e, false
	}
	if escQuote(v, j) {
		out.WriteString(v[p:j+2] + r.ph)
		e := escEnd(v, j)
		return e, e < 0
	}
	switch q := v[j]; {
	case isQuote(q):
		out.WriteString(v[p:j+1] + r.ph)
		e := quoteEnd(v, j)
		return e, e < 0
	case q == '{' || q == '[':
		if strings.TrimLeft(v[j+1:], " \t\r\n") == "" {
			out.WriteString(v[p:j])
			return j, false
		}
		out.WriteString(v[p:j] + r.ph)
		return 0, true
	}
	e := runEnd(v, j)
	if e == j {
		out.WriteString(v[p:j])
		return j, false
	}
	out.WriteString(v[p:j] + r.ph)
	return e, false
}
