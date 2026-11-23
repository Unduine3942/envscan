// api_data.go: the data model shared by every file (owner: main; change only through main).
//
// A probe builds its data from *Obj (ordered object), []any (array) and scalar values. Every
// string reaches the report through the redaction pass (finalize, engine), exactly like the
// event types of src/sh/awk/json.awk:
//
//	string    -> redactValue (sh es_s)       Named   -> redactNamed(Name, Value) (sh es_e)
//	Line      -> redactLine (sh es_l)        Cmd     -> redactCmd (sh es_c)
//	Text      -> redactText, capped at Max bytes (sh es_f / es_raw)
//	Verbatim  -> never redacted (ids and values the scanner made itself; sh "x")
//	NumText   -> a number taken from text (sh es_n); use num(s), which gives nil for "" and a
//	             plain string (redacted) for non-numeric text
//	nil -> null, bool, int, int64, uint64, float64 as they are.
package main

import "strings"

// Obj is an object whose keys keep their first insertion position. Set on an existing key
// replaces the value in place (sh es_dedup_last: first position, last value).
type Obj struct {
	keys []string
	vals map[string]any
}

func NewObj() *Obj { return &Obj{vals: map[string]any{}} }

// Set stores v under k and returns o (chainable).
func (o *Obj) Set(k string, v any) *Obj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *Obj) Get(k string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[k]
	return v, ok
}

// Str is the string value of k ("" when absent or not a plain string-like value).
func (o *Obj) Str(k string) string {
	v, _ := o.Get(k)
	return plainString(v)
}

// Keys returns a copy of the keys in order.
func (o *Obj) Keys() []string {
	if o == nil {
		return nil
	}
	return append([]string(nil), o.keys...)
}

func (o *Obj) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

type Named struct{ Name, Value string }
type Line string
type Cmd string
type Text struct {
	Body string
	Max  int
}
type Verbatim string
type NumText string

// plainString unwraps the string kinds (no redaction).
func plainString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case Verbatim:
		return string(t)
	case Line:
		return string(t)
	case Cmd:
		return string(t)
	case NumText:
		return string(t)
	case Named:
		return t.Value
	case Text:
		return t.Body
	}
	return ""
}

// num is sh es_n: nil for "", NumText for -?digits(.digits)? (leading zeros dropped and -0 made 0,
// like json.awk num_text), else the string itself (redacted like any string).
func num(s string) any {
	if s == "" {
		return nil
	}
	if n, ok := numText(s); ok {
		return NumText(n)
	}
	return s
}

// strOrNil is sh es_sn: nil for "", else the string.
func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// boolOrNil is sh es_b: true/false for "true"/"false", else nil.
func boolOrNil(s string) any {
	switch s {
	case "true":
		return true
	case "false":
		return false
	}
	return nil
}

func numText(s string) (string, bool) {
	neg := strings.HasPrefix(s, "-")
	v := strings.TrimPrefix(s, "-")
	intPart, frac, hasDot := strings.Cut(v, ".")
	if !allDigits(intPart) || (hasDot && !allDigits(frac)) {
		return "", false
	}
	for len(v) > 1 && v[0] == '0' && v[1] != '.' {
		v = v[1:]
	}
	if neg && v != "0" {
		return "-" + v, true
	}
	return v, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// lines splits text into lines without the trailing CR; the last empty line is dropped.
func lines(text string) []string {
	if text == "" {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// nonEmptyLines is lines without the empty ones (sh es_list).
func nonEmptyLines(text string) []any {
	out := []any{}
	for _, l := range lines(text) {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
