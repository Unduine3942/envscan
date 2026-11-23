// engine_json.go: the JSON writer of json.awk (mode json) for a finalized document: two-space
// indentation, pure ASCII (\uXXXX for everything else, invalid UTF-8 as U+FFFD), arrays of
// scalars on one line ("[a, b]") until they pass 16 items or 100 characters, then one item per
// line, and a line break after the top-level object.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	arrayInlineItems = 16
	arrayInlineChars = 100
)

// writeJSON renders a finalized document.
func writeJSON(doc *Obj) string {
	var b strings.Builder
	writeObj(&b, doc, 1)
	b.WriteString("\n")
	return b.String()
}

func ind(d int) string { return strings.Repeat("  ", d) }

// writeObj writes an object whose members sit at depth d.
func writeObj(b *strings.Builder, o *Obj, d int) {
	b.WriteString("{")
	keys := o.Keys()
	if len(keys) == 0 {
		b.WriteString("}")
		return
	}
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\n" + ind(d) + jstr(k) + ": ")
		v, _ := o.Get(k)
		writeValue(b, v, d+1)
	}
	b.WriteString("\n" + ind(d-1) + "}")
}

// writeValue writes v; d is the depth its own members would have.
func writeValue(b *strings.Builder, v any, d int) {
	switch t := v.(type) {
	case *Obj:
		writeObj(b, t, d)
	case []any:
		writeArray(b, t, d)
	default:
		b.WriteString(scalarJSON(v))
	}
}

// writeArray follows json.awk: scalars are held back while the array may still fit on one line.
func writeArray(b *strings.Builder, items []any, d int) {
	var pend []string
	pending, length, cnt := true, 0, 0
	flush := func() {
		b.WriteString("[")
		for i, s := range pend {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("\n" + ind(d) + s)
		}
		cnt, pending = len(pend), false
	}
	for _, it := range items {
		_, isObj := it.(*Obj)
		_, isArr := it.([]any)
		if pending && !isObj && !isArr {
			s := scalarJSON(it)
			pend = append(pend, s)
			length += len(s) + 2
			if length > arrayInlineChars || len(pend) > arrayInlineItems {
				flush()
			}
			continue
		}
		if pending {
			flush()
		}
		if cnt > 0 {
			b.WriteString(",")
		}
		cnt++
		b.WriteString("\n" + ind(d))
		writeValue(b, it, d+1)
	}
	switch {
	case pending:
		b.WriteString("[" + strings.Join(pend, ", ") + "]")
	case cnt == 0:
		b.WriteString("]")
	default:
		b.WriteString("\n" + ind(d-1) + "]")
	}
}

func scalarJSON(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case NumText:
		return string(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case string:
		return jstr(t)
	}
	return jstr(fmt.Sprint(v))
}

// jstr is json.awk jstr: \" \\ \n \r \t \b \f, other controls and DEL as \u00XX, valid UTF-8
// as \uXXXX (surrogate pairs above U+FFFF), each invalid byte as U+FFFD.
func jstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x80 {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size <= 1 {
				writeUcode(&b, 0xfffd)
				i++
				continue
			}
			writeUcode(&b, r)
			i += size
			continue
		}
		b.WriteString(asciiEscape(c))
		i++
	}
	b.WriteByte('"')
	return b.String()
}

func asciiEscape(c byte) string {
	switch c {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	}
	if c < 0x20 || c == 0x7f {
		return fmt.Sprintf(`\u%04x`, c)
	}
	return string(c)
}

func writeUcode(b *strings.Builder, r rune) {
	if r < 0x10000 {
		fmt.Fprintf(b, `\u%04x`, r)
		return
	}
	r -= 0x10000
	fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
}
