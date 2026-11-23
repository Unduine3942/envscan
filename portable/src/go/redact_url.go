// redact_url.go: VALUE RULES "url userinfo", "conda token" and "bare userinfo" (redact_url,
// redact_userinfo, ui_token, ui_host of redact.awk).
package main

import "strings"

func isSchemeByte(c byte) bool { return isAlnum(c) || c == '+' || c == '.' || c == '-' }

// redactURL: scheme://user:password@host (the password to the LAST "@" of the authority),
// scheme://<long token>@host, and conda "/t/<token>/" path segments
func (r *redactRules) redactURL(v string) string {
	var out strings.Builder
	w, p := v, 0
	sep, ws, conda := newFinder(w, "://"), &wsFinder{s: w}, newFinder(w, "/t/")
	for {
		k := sep.next(p)
		if k < 0 {
			break
		}
		var c byte
		if k > p {
			c = w[k-1]
		}
		out.WriteString(w[p : k+3])
		p = k + 3
		if !isSchemeByte(c) {
			continue
		}
		p = r.urlUserinfo(&out, w, p)
		re := ws.next(p)
		if t := conda.next(p); t < 0 || t >= re {
			continue
		}
		if repl, ok := r.condaRun(w[p:re]); ok {
			w = repl + w[re:]
			p = 0
			sep, ws, conda = newFinder(w, "://"), &wsFinder{s: w}, newFinder(w, "/t/")
		}
	}
	out.WriteString(w[p:])
	return out.String()
}

// urlUserinfo: the authority at w[p:]; writes user:<redacted>@ or <redacted>@ and returns the
// position after the "@", else p
func (r *redactRules) urlUserinfo(out *strings.Builder, w string, p int) int {
	j := p
	for j < len(w) && w[j] != '/' && w[j] != '?' && w[j] != '#' && !isWS(w[j]) {
		j++
	}
	auth := w[p:j]
	last := strings.LastIndexByte(auth, '@')
	if last < 0 {
		return p
	}
	if colon := strings.IndexByte(auth, ':'); colon >= 0 && colon < last {
		out.WriteString(auth[:colon+1] + r.ph + "@")
		return p + last + 1
	}
	first := strings.IndexByte(auth, '@')
	if first >= r.minLen && !strings.Contains(auth[:first], ":") {
		out.WriteString(r.ph + "@")
		return p + first + 1
	}
	return p
}

// condaRun: the first "/t/<8+ characters>/" segment of a run replaced, ok when one was
func (r *redactRules) condaRun(run string) (string, bool) {
	var s2 strings.Builder
	q := run
	for {
		pp := strings.Index(q, "/t/")
		if pp < 0 {
			return run, false
		}
		seg := q[pp+3:]
		if e := strings.IndexByte(seg, '/'); e >= 8 {
			s2.WriteString(q[:pp+3] + r.ph)
			s2.WriteString(seg[e:])
			return s2.String(), true
		}
		s2.WriteString(q[:pp+1])
		q = q[pp+1:]
	}
}

// wsFinder: the next whitespace at or after a position (cached, see finder)
type wsFinder struct {
	s     string
	pos   int
	lo    int
	valid bool
}

func (f *wsFinder) next(p int) int {
	if f.valid && p >= f.lo && f.pos >= p {
		return f.pos
	}
	f.valid, f.lo = true, p
	j := p
	for j < len(f.s) && !isWS(f.s[j]) {
		j++
	}
	f.pos = j
	return j
}

func isTokenSep(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || isQuote(c) }

// redactUserinfo: the bare userinfo rule in every token (a run without whitespace or quotes)
func (r *redactRules) redactUserinfo(v string) string {
	var out strings.Builder
	i := 0
	for i < len(v) {
		if isTokenSep(v[i]) {
			out.WriteByte(v[i])
			i++
			continue
		}
		j := i
		for j < len(v) && !isTokenSep(v[j]) {
			j++
		}
		t := v[i:j]
		if strings.IndexByte(t, '@') >= 0 && strings.IndexByte(t, ':') >= 0 {
			t = r.uiToken(t)
		}
		out.WriteString(t)
		i = j
	}
	return out.String()
}

func isUISegSep(c byte) bool { return c == '=' || c == ';' || c == ',' || c == '(' || c == '|' }

// uiSegments: the segment start offsets of t split at = ; , ( | (each segment ends at the
// next separator or the end)
func uiSegments(t string) []int {
	starts := []int{0}
	for i := 0; i < len(t); i++ {
		if isUISegSep(t[i]) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// uiToken: user:password@host[:port] inside one token (ui_token); the fallback replaces the
// whole token when an over-long user or password is followed by an "@"
func (r *redactRules) uiToken(t string) string {
	starts := uiSegments(t)
	var out strings.Builder
	last, st, i := 0, 0, 0
	for i < len(starts) {
		end := len(t)
		if i+1 < len(starts) {
			end = starts[i+1] - 1
		}
		if end < st {
			i++
			continue
		}
		segStart := starts[i]
		if st > segStart {
			segStart = st
		}
		if ca, a, h := uiMatch(t, segStart, end); h > 0 {
			out.WriteString(t[last:ca+1] + r.ph + "@" + t[ca+a+2:ca+a+2+h])
			last = ca + a + 2 + h
			st = last + 1
			continue
		}
		st = end + 1
		i++
	}
	if last > 0 {
		out.WriteString(t[last:])
		return out.String()
	}
	return r.uiFallback(t)
}

// uiMatch: in the segment t[s:end], a user (1-128 characters, no "/") up to the first ":" and
// a password (1-256 characters, no "/" or "\") up to an "@" followed by a host. Returns the
// index of the ":", the offset of the "@" after it, and the host length (0: no match).
func uiMatch(t string, s, end int) (ca, a, h int) {
	seg := t[s:end]
	c := strings.IndexByte(window(seg, 0, 129), ':')
	if c < 1 || strings.IndexByte(seg[:c], '/') >= 0 {
		return 0, 0, 0
	}
	ca = s + c
	w := window(t, ca+1, 257)
	rp := strings.IndexAny(w, `/\`)
	off := 0
	for {
		k := strings.IndexByte(w[off:], '@')
		if k < 0 {
			return 0, 0, 0
		}
		a = off + k
		if a == 0 || (rp >= 0 && a > rp) {
			return 0, 0, 0
		}
		if h = uiHost(window(t, ca+a+2, 270)); h > 0 {
			return ca, a, h
		}
		off = a + 1
	}
}

func (r *redactRules) uiFallback(t string) string {
	fc := strings.IndexByte(t, ':')
	if fc < 0 {
		return t
	}
	tail := t[fc+1:]
	rl := strings.IndexAny(tail, `/\`)
	if rl < 0 {
		rl = len(tail)
	}
	if fc >= 129 && rl >= 2 && strings.IndexByte(tail[1:rl], '@') >= 0 {
		return r.ph
	}
	if rl >= 257 && strings.IndexByte(tail[257:rl], '@') >= 0 {
		return r.ph
	}
	return t
}

func isHostByte(c byte) bool { return isAlnum(c) || c == '.' || c == '_' || c == '-' }

func isIPv6Byte(c byte) bool {
	return isDigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || c == ':' || c == '.'
}

// hostRun: the length of [IPv6] or [A-Za-z0-9._-]+ at the start of s, 0 when none
func hostRun(s string) int {
	if at(s, 0) == '[' {
		j := 1
		for j < len(s) && isIPv6Byte(s[j]) {
			j++
		}
		if j > 1 && at(s, j) == ']' {
			return j + 1
		}
	}
	j := 0
	for j < len(s) && isHostByte(s[j]) {
		j++
	}
	return j
}

// uiHost: the length of host[:port] at the start of s when the end of s or a userinfo end
// character follows it (after a port also "." or "!"), else 0
func uiHost(s string) int {
	n := hostRun(s)
	if n == 0 {
		return 0
	}
	port := false
	if at(s, n) == ':' {
		d := n + 1
		for d < len(s) && isDigit(s[d]) {
			d++
		}
		if d > n+1 && d-n-1 <= 5 {
			n, port = d, true
		}
	}
	c := at(s, n)
	if n >= len(s) || strings.IndexByte(userinfoEndSet, c) >= 0 {
		return n
	}
	if port && (c == '.' || c == '!') {
		return n
	}
	return 0
}
