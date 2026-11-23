// redact_tools.go: COMMAND LINES "tool options" (tool_in, value_end, redact_toolopt,
// redact_toolopts of redact.awk).
package main

import "strings"

// redactToolOpts: the password options of every tool in tool_options that appears in the line
// as a program name
func (r *redactRules) redactToolOpts(s string) string {
	if len(r.toolNames) == 0 {
		return s
	}
	ls := lowerASCII(s)
	var opts []string
	for _, t := range r.toolNames {
		if strings.Contains(ls, t) && toolIn(ls, t) {
			opts = append(opts, r.toolOpts[t]...)
		}
	}
	for _, o := range opts {
		s = r.redactToolOpt(s, o)
	}
	return s
}

func isToolBefore(c byte) bool { return isWS(c) || strings.IndexByte("\"'/\\;&|(=", c) >= 0 }

// toolIn: the lower-cased line ls holds tool t as a program name: after the start, whitespace,
// a quote or / \ ; & | ( =, with an optional .exe .cmd .bat .com, then whitespace, a quote or
// the end
func toolIn(ls, t string) bool {
	p := 0
	for {
		k := strings.Index(ls[p:], t)
		if k < 0 {
			return false
		}
		k += p
		if k == 0 || isToolBefore(ls[k-1]) {
			a := ls[k+len(t):]
			switch window(a, 0, 4) {
			case ".exe", ".cmd", ".bat", ".com":
				a = a[4:]
			}
			if a == "" || isWS(a[0]) || isQuote(a[0]) {
				return true
			}
		}
		p = k + 1
	}
}

// valueEnd: the end of the value at e: a quoted or escaped-quoted value is one value, else a
// run up to whitespace
func valueEnd(s string, e int) int {
	if escQuote(s, e) {
		if k := escEnd(s, e); k >= 0 {
			return k + 2
		}
		return len(s)
	}
	if isQuote(at(s, e)) {
		if k := quoteEnd(s, e); k >= 0 {
			return k + 1
		}
		return len(s)
	}
	for e < len(s) && !isWS(s[e]) {
		e++
	}
	return e
}

// redactToolOpt: one tool option o after whitespace: o<value> -> o<redacted>,
// o<whitespace><value> -> o<whitespace><redacted>. "-" options are case-sensitive, "/" ones not.
func (r *redactRules) redactToolOpt(s, o string) string {
	hay := s
	if o[0] == '/' {
		o, hay = lowerASCII(o), lowerASCII(s)
	}
	var out strings.Builder
	p := 0
	for {
		k := strings.Index(hay[p:], o)
		if k < 0 {
			break
		}
		k += p
		var b byte
		if k > p {
			b = s[k-1]
		} else if cur := out.String(); cur != "" {
			b = cur[len(cur)-1]
		}
		if isWS(b) {
			if e, v := toolOptValue(s, k+len(o)); v > e {
				out.WriteString(s[p:e] + r.ph)
				p = v
				continue
			}
		}
		out.WriteString(s[p : k+1])
		p = k + 1
	}
	out.WriteString(s[p:])
	return out.String()
}

// toolOptValue: the value after an option ending at j: its start and end (end <= start: none)
func toolOptValue(s string, j int) (int, int) {
	if j >= len(s) {
		return 0, 0
	}
	e := j
	if isWS(s[j]) {
		e = skipWS(s, j)
		if e >= len(s) {
			return 0, 0
		}
	}
	return e, valueEnd(s, e)
}
