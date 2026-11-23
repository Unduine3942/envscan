// report_util.go: helpers shared by the findings, Markdown and brief ports (owner: report).
// Ports of the sh helpers es_join, es_lt, es_flt, es_vercmp, es_oneline and json.awk u8clean.
package main

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---- document access (the finalized report document, see api_services.go)

// objOf is o[k] as *Obj (nil when absent or not an object).
func objOf(o *Obj, k string) *Obj {
	v, _ := o.Get(k)
	x, _ := v.(*Obj)
	return x
}

// listOf is o[k] as []any (nil when absent or not an array).
func listOf(o *Obj, k string) []any {
	v, _ := o.Get(k)
	x, _ := v.([]any)
	return x
}

// scalarText is the text json.awk writes for a scalar: strings as they are, numbers in their
// decimal form, true/false, and "null" for nil. ok=false for objects and arrays.
func scalarText(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "null", true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case *Obj, []any:
		return "", false
	}
	return plainString(v), true
}

// textOf is o[k] as text: "" when absent or null (sh: an empty field).
func textOf(o *Obj, k string) string {
	v, ok := o.Get(k)
	if !ok || v == nil {
		return ""
	}
	s, _ := scalarText(v)
	return s
}

// ---- sh value helpers

// orDefault is sh ${v:-def}.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ifSet is sh ${v:+text}: text when v is not empty.
func ifSet(v, text string) string {
	if v == "" {
		return ""
	}
	return text
}

// appendSep is sh "${a:+$a<sep>}b".
func appendSep(a, sep, b string) string {
	if a == "" {
		return b
	}
	return a + sep + b
}

// shJoin is sh es_join: the lines that hold a non-blank character, joined with ", "; at most max
// items, then ", ... (N in total)".
func shJoin(text string, max int) string {
	var items []string
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if strings.Trim(l, " \t") == "" {
			continue
		}
		n++
		if n <= max {
			items = append(items, l)
		}
	}
	s := strings.Join(items, ", ")
	if n > max {
		s += ", ... (" + strconv.Itoa(n) + " in total)"
	}
	return s
}

// isNum is sh es_is_num: digits only.
func rpIsNum(s string) bool { return allDigits(s) }

// shInt is the value of a digits-only string ("[ -lt ]" fails on anything else or on overflow).
func shInt(s string) (int64, bool) {
	if !rpIsNum(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// shLt is sh es_lt A B: both digits-only and A < B.
func shLt(a, b string) bool {
	x, ok1 := shInt(a)
	y, ok2 := shInt(b)
	return ok1 && ok2 && x < y
}

var awkNumPrefix = regexp.MustCompile(`^[ \t\n]*[-+]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?`)

// awkNumber is awk's string-to-number conversion: the longest numeric prefix, else 0.
func awkNumber(s string) float64 {
	m := awkNumPrefix.FindString(s)
	f, err := strconv.ParseFloat(strings.TrimLeft(m, " \t\n"), 64)
	if err != nil {
		return 0
	}
	return f
}

// awkLess is sh es_flt A B: both non-empty and a + 0 < b + 0 in awk.
func awkLess(a, b string) bool {
	return a != "" && b != "" && awkNumber(a) < awkNumber(b)
}

// awkPrintNum is awk "print x": integers as such, other values with OFMT %.6g.
func awkPrintNum(x float64) string {
	if x == math.Trunc(x) && math.Abs(x) < 1e15 {
		return strconv.FormatInt(int64(x), 10)
	}
	return strconv.FormatFloat(x, 'g', 6, 64)
}

var nonDigits = regexp.MustCompile(`[^0-9]+`)

// vercmp is sh es_vercmp: -1, 0 or 1 comparing the digit groups of a and b numerically.
func vercmp(a, b string) int {
	A, B := awkSplitDigits(a), awkSplitDigits(b)
	n := len(A)
	if len(B) > n {
		n = len(B)
	}
	for i := 0; i < n; i++ {
		x, y := digitAt(A, i), digitAt(B, i)
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func awkSplitDigits(s string) []string {
	if s == "" {
		return nil
	}
	return nonDigits.Split(s, -1)
}

func digitAt(parts []string, i int) float64 {
	if i >= len(parts) {
		return 0
	}
	return awkNumber(parts[i])
}

// ---- text helpers

// u8clean is json.awk u8clean: valid UTF-8 kept, each invalid byte -> "?", ASCII control
// characters -> space.
func u8clean(s string) string {
	plain := true
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] >= 127 {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c >= 32 && c < 127:
			b.WriteByte(c)
			i++
		case c < 32 || c == 127:
			b.WriteByte(' ')
			i++
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size <= 1 {
				b.WriteByte('?')
				i++
				continue
			}
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	return b.String()
}

// validUTF8 replaces each invalid byte with "?" and keeps everything else (the brief: sh writes
// its bytes as they are; the Go port keeps the file valid UTF-8).
func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteByte('?')
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// cutBytes is awk substr(s, 1, n) on bytes; a UTF-8 sequence cut in half is dropped so that
// the result stays valid (deviation from sh, which keeps the partial bytes).
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for k := 1; k <= 3 && k <= len(s); k++ {
		c := s[len(s)-k]
		if c < 0x80 {
			break
		}
		if c >= 0xC0 {
			if r, _ := utf8.DecodeRuneInString(s[len(s)-k:]); r == utf8.RuneError {
				s = s[:len(s)-k]
			}
			break
		}
	}
	return s
}

// oneline is sh es_oneline: newlines, CR and tabs -> spaces; a leading "#" or "- " gets a space.
func oneline(s string) string {
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
	if strings.HasPrefix(s, "#") || strings.HasPrefix(s, "- ") {
		s = " " + s
	}
	return s
}
