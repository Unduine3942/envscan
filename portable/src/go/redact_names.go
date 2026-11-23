// redact_names.go: NAME RULES (secret_name, camel_split) and the quote scanners of redact.awk.
package main

import "strings"

// camelSplit: "_" at camelCase boundaries [a-z0-9][A-Z] and [A-Z]+[A-Z][a-z]
func camelSplit(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
		return s
	}
	var b strings.Builder
	b.WriteByte(s[0])
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			p, q := s[i-1], at(s, i+1)
			lowerDigit := (p >= 'a' && p <= 'z') || isDigit(p)
			if lowerDigit || ((p >= 'A' && p <= 'Z') && q >= 'a' && q <= 'z') {
				b.WriteByte('_')
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// nameSegments: the upper-cased name split on every run outside [A-Z0-9]
func nameSegments(name string) []string {
	return strings.FieldsFunc(upperASCII(camelSplit(name)), func(r rune) bool {
		return !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
}

func (r *redactRules) secretName(name string) bool {
	if name == "" || r.exc[upperASCII(name)] {
		return false
	}
	segs := nameSegments(name)
	if len(segs) == 0 {
		return false
	}
	norm, joined := strings.Join(segs, "_"), strings.Join(segs, "")
	for _, sx := range r.sfxExc {
		if strings.HasSuffix(norm, sx) {
			return false
		}
	}
	for _, s := range segs {
		if r.seg[s] {
			return true
		}
	}
	if containsAny(joined, r.contains) {
		return true
	}
	for _, ns := range r.nameSfx {
		if strings.HasSuffix(joined, ns) {
			return true
		}
	}
	return false
}

// quoteEnd: index of the quote closing the one at s[j], -1 when none. A quote after an odd
// number of backslashes is escaped; in '...' a doubled quote is a literal quote and the shell
// idiom 'a' backslash-quote 'b' continues the value.
func quoteEnd(s string, j int) int {
	q := s[j]
	start := j + 1
	for start <= len(s) {
		k := strings.IndexByte(s[start:], q)
		if k < 0 {
			return -1
		}
		k += start
		b := 0
		for k-b-1 > j && s[k-b-1] == '\\' {
			b++
		}
		if b%2 == 1 {
			start = k + 1
			continue
		}
		if q == '\'' && window(s, k+1, 3) == `\''` {
			start = k + 4
			continue
		}
		if q == '\'' && k > j+1 && at(s, k+1) == '\'' {
			start = k + 2
			continue
		}
		return k
	}
	return -1
}

// escQuote: s[j] is a backslash before a quote (\" or \' opens an escaped-quoted value)
func escQuote(s string, j int) bool {
	return at(s, j) == '\\' && isQuote(at(s, j+1))
}

// escEnd: s[j] opens \" (or \'); the index of the backslash of the closing pair, -1 when the
// string is unterminated
func escEnd(s string, j int) int {
	t := s[j : j+2]
	start := j + 2
	for start <= len(s) {
		k := strings.Index(s[start:], t)
		if k < 0 {
			return -1
		}
		k += start
		if k > j+2 && s[k-1] == '\\' {
			start = k + 2
			continue
		}
		return k
	}
	return -1
}

// skipQuote: after a quote or an escaped quote at s[j], else j
func skipQuote(s string, j int) int {
	if isQuote(at(s, j)) {
		return j + 1
	}
	if escQuote(s, j) {
		return j + 2
	}
	return j
}
