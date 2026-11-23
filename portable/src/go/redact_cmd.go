// redact_cmd.go: COMMAND LINES (redact_options, redact_useropt, redact_headers,
// redact_toolopts, redact_cmdline, redact_named of redact.awk).
package main

import "strings"

func (r *redactRules) cmdline(s string) string {
	if s == "" {
		return s
	}
	if len(s) > redactMaxLen {
		return redactTooLong
	}
	// tool options first: an attached value (7z -pSecretPw) would read as an option name
	s = r.redactToolOpts(s)
	s = r.redactOptions(s)
	if strings.IndexByte(s, ':') >= 0 {
		s = r.redactUserOpt(s)
	}
	if strings.IndexByte(s, ':') >= 0 {
		s = r.redactHeaders(s)
	}
	return r.value(s)
}

// named: a secret name loses its value; any other value gets the command-line and value rules
func (r *redactRules) named(name, v string) string {
	if v == "" {
		return v
	}
	if r.secretName(name) {
		return r.ph
	}
	if len(v) > redactMaxLen {
		return redactTooLong
	}
	return r.cmdline(v)
}

// optionStart: s[i] is "-" or "/" at the start or after whitespace
func optionStart(s string, i int, slash bool) bool {
	c := s[i]
	return (c == '-' || (slash && c == '/')) && (i == 0 || isWS(s[i-1]))
}

// redactOptions: (-|--|/)<name containing an option word>(=|:|whitespace)<value>
func (r *redactRules) redactOptions(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if !optionStart(s, i, true) {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := i + 1
		if s[i] == '-' && at(s, j) == '-' {
			j++
		}
		k := j
		for k < len(s) && isKeyByte(s[k]) {
			k++
		}
		if containsAny(lowerASCII(s[j:k]), r.optWords) && k < len(s) {
			if next, ok := r.optionValue(&out, s, i, k); ok {
				i = next
				continue
			}
		}
		if k <= i {
			k = i + 1
		}
		out.WriteString(s[i:k])
		i = k
	}
	return out.String()
}

// optionValue: the value after the option name ending at k; writes s[i:...] and the placeholder
func (r *redactRules) optionValue(out *strings.Builder, s string, i, k int) (int, bool) {
	q := s[k]
	if q != '=' && q != ':' && !isWS(q) {
		return 0, false
	}
	e := k + 1
	if isWS(q) {
		e = skipWS(s, e)
	}
	if e >= len(s) {
		return 0, false
	}
	if escQuote(s, e) {
		v := escEnd(s, e)
		if v < 0 {
			v = len(s)
		}
		out.WriteString(s[i:e+2] + r.ph)
		return v, true
	}
	v := -1
	if isQuote(s[e]) {
		if c := quoteEnd(s, e); c >= 0 {
			v = c + 1
		}
	}
	if v < 0 {
		v = e
		for v < len(s) && !isWS(s[v]) {
			v++
		}
	}
	if v <= e {
		return 0, false
	}
	out.WriteString(s[i:e] + r.ph)
	return v, true
}

// userOptLen: the length of -u / --user / --proxy-user at s[i:] (any case), 0 when none
func userOptLen(s string, i int) int {
	lo := lowerASCII(window(s, i, 12))
	switch {
	case lo == "--proxy-user":
		return 12
	case strings.HasPrefix(lo, "--user"):
		return 6
	case strings.HasPrefix(lo, "-u"):
		return 2
	}
	return 0
}

// redactUserOpt: -u / --user / --proxy-user user:secret -> user:<redacted>, also attached
func (r *redactRules) redactUserOpt(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if optionStart(s, i, false) {
			if o := userOptLen(s, i); o > 0 {
				if next, ok := r.userOptValue(&out, s, i, o); ok {
					i = next
					continue
				}
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func (r *redactRules) userOptValue(out *strings.Builder, s string, i, o int) (int, bool) {
	j := i + o
	k := j
	for k < len(s) && (isWS(s[k]) || s[k] == '=') {
		k++
	}
	if c := at(s, j); !(k > j || (o == 2 && j < len(s) && c != '-')) {
		return 0, false
	}
	qa := -1
	if isQuote(at(s, k)) {
		qa = k
		k++
	}
	u := k
	for k < len(s) && !isWS(s[k]) && s[k] != ':' && !isQuote(s[k]) {
		k++
	}
	if k == u || at(s, k) != ':' {
		return 0, false
	}
	e := k + 1
	if qa >= 0 {
		if e = quoteEnd(s, qa); e < 0 {
			e = len(s)
		}
	} else {
		e = quotedRunEnd(s, e)
	}
	if e <= k+1 {
		return 0, false
	}
	out.WriteString(s[i:k+1] + r.ph)
	return e, true
}

// quotedRunEnd: a run of text and quoted pieces (bob:'pa ss'x) from e, ending at whitespace
func quotedRunEnd(s string, e int) int {
	for e < len(s) {
		c := s[e]
		if isQuote(c) {
			if v := quoteEnd(s, e); v >= 0 {
				e = v + 1
			} else {
				e = len(s)
			}
			continue
		}
		if isWS(c) {
			break
		}
		e++
	}
	return e
}

// headerOptLen: the length of -H / --header at s[i:] (any case), 0 when none
func headerOptLen(s string, i int) int {
	lo := lowerASCII(window(s, i, 8))
	switch {
	case lo == "--header":
		return 8
	case strings.HasPrefix(lo, "-h"):
		return 2
	}
	return 0
}

func isHeaderNameByte(c byte) bool { return isAlnum(c) || c == '-' }

// redactHeaders: -H / --header "Name: value" where Name contains a header word
func (r *redactRules) redactHeaders(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if optionStart(s, i, false) {
			if o := headerOptLen(s, i); o > 0 {
				if next, ok := r.headerValue(&out, s, i, o); ok {
					i = next
					continue
				}
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func (r *redactRules) headerValue(out *strings.Builder, s string, i, o int) (int, bool) {
	j := i + o
	k := j
	for k < len(s) && (isWS(s[k]) || s[k] == '=') {
		k++
	}
	if k == j {
		return 0, false
	}
	if isQuote(at(s, k)) {
		k++
	}
	h := k
	for k < len(s) && isHeaderNameByte(s[k]) {
		k++
	}
	if !containsAny(lowerASCII(s[h:k]), r.hdrWords) {
		return 0, false
	}
	k = skipWS(s, k)
	if at(s, k) != ':' || k >= len(s) {
		return 0, false
	}
	k = skipWS(s, k+1)
	e := k
	for e < len(s) && !isQuote(s[e]) && s[e] != '\r' && s[e] != '\n' {
		e++
	}
	if e <= k {
		return 0, false
	}
	out.WriteString(s[i:k] + r.ph)
	return e, true
}
