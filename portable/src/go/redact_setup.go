// redact_setup.go: the redaction tables (spec/redaction.toml through the embedded spec, the same
// keys envscan.sh gets) and the byte helpers shared by the redact_*.go files.
//
// Port of src/sh/awk/redact.awk, which runs with LC_ALL=C: every rule works on bytes, case
// folding is ASCII only and every cut point is an ASCII delimiter, so a multibyte UTF-8
// character is never split and invalid UTF-8 passes through unchanged. Indexes are 0-based
// (awk's are 1-based); "none" is -1 where awk returns 0.
package main

import (
	"fmt"
	"strings"
)

const (
	redactMaxLen   = 131072 // spec "LENGTH CAP"
	redactTooLong  = "<redacted: too long>"
	redactPKText   = "<redacted: private key>"
	runSeparators  = ",;&#}])\"'<>|"
	userinfoEndSet = "/,;)]}><|&#?\\"
)

type redactRules struct {
	ph        string
	seg       map[string]bool
	contains  []string
	nameSfx   []string
	exc       map[string]bool
	sfxExc    []string
	prefixes  []string
	minLen    int
	pairKeys  []string // lower case
	optWords  []string // lower case
	hdrWords  []string // lower case
	xmlEl     []string // lower case
	xmlAt     []string // lower case
	pkMarker  string
	xmlWords  []string // name_contains (lower) + pwd, pass: secret words of key="..." / name="..."
	toolNames []string // lower case, first-seen order
	toolOpts  map[string][]string
}

var rr *redactRules

func init() {
	rr = newRedactRules(spec.Redaction)
	redactValue = func(s string) string { return rr.value(s) }
	redactNamed = func(name, value string) string { return rr.named(name, value) }
	redactLine = func(s string) string { return rr.line(s) }
	redactText = func(s string) string { return rr.text(s) }
	redactCmd = func(s string) string { return rr.cmdline(s) }
	isSecretName = func(name string) bool { return rr.secretName(name) }
}

func specWords(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		panic(fmt.Sprintf("embedded spec: redaction.%s is not a list", key))
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			panic(fmt.Sprintf("embedded spec: redaction.%s holds a non-string", key))
		}
		out = append(out, s)
	}
	return out
}

func specString(m map[string]any, key, def string) string {
	if s, ok := m[key].(string); ok && s != "" {
		return s
	}
	return def
}

func wordSet(words []string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, w := range words {
		set[w] = true
	}
	return set
}

func lowerAll(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = lowerASCII(w)
	}
	return out
}

func newRedactRules(m map[string]any) *redactRules {
	r := &redactRules{
		ph:       specString(m, "placeholder", "<redacted>"),
		seg:      wordSet(specWords(m, "name_segments")),
		contains: specWords(m, "name_contains"),
		nameSfx:  specWords(m, "name_suffixes"),
		exc:      wordSet(specWords(m, "exact_exceptions")),
		sfxExc:   specWords(m, "suffix_exceptions"),
		prefixes: specWords(m, "token_prefixes"),
		minLen:   20,
		pairKeys: lowerAll(specWords(m, "pair_keys")),
		optWords: lowerAll(specWords(m, "option_words")),
		hdrWords: lowerAll(specWords(m, "header_words")),
		xmlEl:    lowerAll(specWords(m, "xml_elements")),
		xmlAt:    lowerAll(specWords(m, "xml_attributes")),
		pkMarker: specString(m, "private_key_marker", "PRIVATE KEY"),
		toolOpts: map[string][]string{},
	}
	if n, ok := m["token_min_length"].(float64); ok && n > 0 {
		r.minLen = int(n)
	}
	r.xmlWords = append(lowerAll(r.contains), "pwd", "pass")
	for _, to := range specWords(m, "tool_options") {
		p := strings.IndexByte(to, ':')
		if p < 1 || p == len(to)-1 {
			continue
		}
		t := lowerASCII(to[:p])
		if _, seen := r.toolOpts[t]; !seen {
			r.toolNames = append(r.toolNames, t)
		}
		r.toolOpts[t] = append(r.toolOpts[t], to[p+1:])
	}
	return r
}

// ------------------------------------------------------------------ byte helpers

func isWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool { return isAlpha(c) || isDigit(c) }

// isWordByte: [A-Za-z0-9_] (awk is_word)
func isWordByte(c byte) bool { return isAlnum(c) || c == '_' }

// isKeyByte: [A-Za-z0-9_.-] (pair and option keys)
func isKeyByte(c byte) bool { return isWordByte(c) || c == '.' || c == '-' }

// isLineKeyByte: [A-Za-z0-9_.:/@$-] (line keys, space pairs, block keys)
func isLineKeyByte(c byte) bool {
	return isKeyByte(c) || c == ':' || c == '/' || c == '@' || c == '$'
}

func isQuote(c byte) bool { return c == '"' || c == '\'' }

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// at: s[i], or 0 outside s (awk substr past the end is "")
func at(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// from: s[i:], "" past the end
func from(s string, i int) string {
	if i >= len(s) {
		return ""
	}
	return s[i:]
}

// window: s[i:i+n] clipped to s
func window(s string, i, n int) string {
	if i >= len(s) {
		return ""
	}
	if i+n > len(s) {
		return s[i:]
	}
	return s[i : i+n]
}

func skipWS(s string, j int) int {
	for j < len(s) && isWS(s[j]) {
		j++
	}
	return j
}

func skipBlank(s string, j int) int {
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return j
}

func leadingBlank(s string) int { return skipBlank(s, 0) }

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// finder: the next index of a fixed substring in a fixed string at or after a position,
// cached so that a scan whose position only grows stays linear.
type finder struct {
	s, sub string
	pos    int // cached absolute index; -1 none after lo
	lo     int // pos is valid for queries >= lo while pos == -1 or pos >= query
	valid  bool
}

func newFinder(s, sub string) *finder { return &finder{s: s, sub: sub} }

func (f *finder) next(p int) int {
	if f.valid && p >= f.lo && (f.pos < 0 || f.pos >= p) {
		return f.pos
	}
	f.valid, f.lo = true, p
	if p > len(f.s) {
		f.pos = -1
		return -1
	}
	k := strings.Index(f.s[p:], f.sub)
	if k < 0 {
		f.pos = -1
	} else {
		f.pos = p + k
	}
	return f.pos
}
