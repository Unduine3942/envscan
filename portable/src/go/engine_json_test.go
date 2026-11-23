package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestJstrEscapes(t *testing.T) {
	bs := `\`
	cases := map[string]string{
		"plain":            `"plain"`,
		`a"b\c`:            `"a\"b\\c"`,
		"l1\nl2\r\t\b\f":   `"l1\nl2\r\t\b\f"`,
		"\x01\x1f\x7f":     `"` + bs + "u0001" + bs + "u001f" + bs + `u007f"`,
		"caf\xc3\xa9":      `"caf` + bs + `u00e9"`,
		"\xf0\x9f\x98\x80": `"` + bs + "ud83d" + bs + `ude00"`,
		"a\xffb":           `"a` + bs + `ufffdb"`,
		"\xc0\xaf":         `"` + bs + "ufffd" + bs + `ufffd"`,
		"\xed\xa0\x80":     `"` + strings.Repeat(bs+"ufffd", 3) + `"`,
		"\xef\xbf\xbd":     `"` + bs + `ufffd"`,
	}
	for in, want := range cases {
		if got := jstr(in); got != want {
			t.Errorf("jstr(%q)=%s want %s", in, got, want)
		}
	}
}

func TestWriteJSONLayout(t *testing.T) {
	doc := NewObj().Set("a", "x").Set("empty_o", NewObj()).Set("empty_a", []any{}).
		Set("short", []any{"p", NumText("1"), true, nil}).
		Set("nested", NewObj().Set("arr", []any{NewObj().Set("k", int64(1)), []any{}}))
	want := `{
  "a": "x",
  "empty_o": {},
  "empty_a": [],
  "short": ["p", 1, true, null],
  "nested": {
    "arr": [
      {
        "k": 1
      },
      []
    ]
  }
}
`
	if got := writeJSON(doc); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestWriteJSONLongArrays(t *testing.T) {
	var many []any
	for i := 0; i < 17; i++ {
		many = append(many, i)
	}
	long := []any{strings.Repeat("a", 60), strings.Repeat("b", 60)}
	doc := NewObj().Set("many", many).Set("long", long).Set("mixed", []any{"s", NewObj()})
	got := writeJSON(doc)
	if !strings.Contains(got, "\"long\": [\n    \""+long[0].(string)+"\",\n    \""+long[1].(string)+"\"\n  ]") {
		t.Fatalf("long:\n%s", got)
	}
	if !strings.Contains(got, "\"many\": [\n    0,\n") || !strings.Contains(got, "    16\n  ]") {
		t.Fatalf("many:\n%s", got)
	}
	if !strings.Contains(got, "\"mixed\": [\n    \"s\",\n    {}\n  ]") {
		t.Fatalf("mixed:\n%s", got)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(got); i++ {
		if got[i] > 0x7e || (got[i] < 0x20 && got[i] != '\n') {
			t.Fatalf("non-ASCII byte at %d", i)
		}
	}
}

func TestScalarJSON(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{{nil, "null"}, {false, "false"}, {7, "7"}, {int64(-2), "-2"}, {uint64(18446744073709551615), "18446744073709551615"},
		{1.5, "1.5"}, {NumText("007"), "007"}, {fmt.Errorf("e"), `"e"`}}
	for _, c := range cases {
		if got := scalarJSON(c.v); got != c.want {
			t.Errorf("%#v: %s", c.v, got)
		}
	}
}
