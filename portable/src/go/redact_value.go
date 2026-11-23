// redact_value.go: VALUE RULES "tokens" and "auth schemes", and redact_value itself
// (redact_tokens, redact_scheme_word, redact_authz of redact.awk).
package main

import "strings"

func (r *redactRules) value(v string) string {
	if v == "" {
		return v
	}
	if len(v) > redactMaxLen {
		return redactTooLong
	}
	if strings.Contains(v, r.pkMarker) {
		return redactPKText
	}
	if strings.Contains(v, "://") {
		v = r.redactURL(v)
	}
	if strings.IndexByte(v, '@') > 0 && strings.IndexByte(v, ':') >= 0 {
		v = r.redactUserinfo(v)
	}
	v = r.redactTokens(v)
	lv := lowerASCII(v)
	if strings.Contains(lv, "bearer") || strings.Contains(lv, "basic") {
		v = r.redactSchemeWord(v)
	}
	if strings.Contains(lowerASCII(v), "authorization") {
		v = r.redactAuthz(v)
	}
	if strings.ContainsAny(v, ":=") {
		v = r.redactPairKeys(v)
		v = r.redactPairs(v)
	}
	return v
}

func isTokenByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == '.' || c == '+' || c == '/' || c == '=' || c == '-'
}

// redactTokens: runs of [A-Za-z0-9_.+/=-] that start with a known prefix (not after a word
// character or "-") and are at least token_min_length long
func (r *redactRules) redactTokens(v string) string {
	if len(v) < r.minLen {
		return v
	}
	for _, pre := range r.prefixes {
		if !strings.Contains(v, pre) {
			continue
		}
		need := len(pre) + 4
		if need < r.minLen {
			need = r.minLen
		}
		v = r.tokensOf(v, pre, need)
	}
	return v
}

func (r *redactRules) tokensOf(v, pre string, need int) string {
	var out strings.Builder
	p := 0
	for {
		k := strings.Index(v[p:], pre)
		if k < 0 {
			break
		}
		k += p
		prevOK := k == p || !(isWordByte(v[k-1]) || v[k-1] == '-')
		if prevOK {
			j := k + len(pre)
			for j < len(v) && isTokenByte(v[j]) {
				j++
			}
			if j-k >= need {
				out.WriteString(v[p:k] + r.ph)
				p = j
				continue
			}
		}
		out.WriteString(v[p : k+len(pre)])
		p = k + len(pre)
	}
	out.WriteString(v[p:])
	return out.String()
}

func isCredByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '-'
}

// redactSchemeWord: "Bearer <8+ chars>" and "Basic <8+ chars>" -> "Bearer <redacted>"
func (r *redactRules) redactSchemeWord(v string) string {
	lv := lowerASCII(v)
	fb, fc := newFinder(lv, "bearer"), newFinder(lv, "basic")
	var out strings.Builder
	p := 0
	for {
		kb, kc := fb.next(p), fc.next(p)
		if kb < 0 && kc < 0 {
			break
		}
		k, w := kc, 5
		if kb >= 0 && (kc < 0 || kb < kc) {
			k, w = kb, 6
		}
		var c byte
		if k > p {
			c = v[k-1]
		}
		j := skipWS(v, k+w)
		if !isWordByte(c) && j > k+w {
			s := j
			for j < len(v) && isCredByte(v[j]) {
				j++
			}
			if j-s >= 8 {
				for j < len(v) && v[j] == '=' {
					j++
				}
				out.WriteString(v[p:k+w] + " " + r.ph)
				p = j
				continue
			}
		}
		out.WriteString(v[p : k+w])
		p = k + w
	}
	out.WriteString(v[p:])
	return out.String()
}

// authzEnd: the end of credentials from j: whitespace, a quote, "," ";" or an escaped quote
func authzEnd(s string, j int) int {
	for j < len(s) {
		c := s[j]
		if isWS(c) || isQuote(c) || c == ',' || c == ';' || escQuote(s, j) {
			break
		}
		j++
	}
	return j
}

// redactAuthz: <key ending in authorization> [quote] [:=] [quote] [scheme] <credentials>
func (r *redactRules) redactAuthz(v string) string {
	fa := newFinder(lowerASCII(v), "authorization")
	var out strings.Builder
	p := 0
	for {
		k := fa.next(p)
		if k < 0 {
			break
		}
		j := skipWS(v, skipQuote(v, k+13))
		if c := at(v, j); c != ':' && c != '=' {
			out.WriteString(v[p : k+13])
			p = k + 13
			continue
		}
		j = skipQuote(v, skipWS(v, j+1))
		j0, s := j, j
		for s < len(v) && isAlpha(v[s]) {
			s++
		}
		if s > j && s < len(v) && isWS(v[s]) {
			j = skipWS(v, s)
		}
		s = authzEnd(v, j)
		if s == j && j != j0 {
			j = j0
			s = authzEnd(v, j)
		}
		if s > j {
			out.WriteString(v[p:j] + r.ph)
		} else {
			out.WriteString(v[p:j])
			s = j
		}
		p = s
	}
	out.WriteString(v[p:])
	return out.String()
}
