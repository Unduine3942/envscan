package main

import (
	"strings"
	"testing"
)

func TestFinalizeKinds(t *testing.T) {
	installStandIns(t)
	in := NewObj().Set("s", "a SECRET").Set("v", Verbatim("SECRET id")).Set("e", Named{"MY_TOKEN", "abc"}).
		Set("e2", Named{"PATH", "/bin"}).Set("l", Line("x=SECRET\ny")).Set("c", Cmd("run\r\nSECRET")).
		Set("n", NumText("5")).Set("arr", []any{"SECRET", []string{"SECRET"}}).Set("b", true).
		Set("i32", int32(3)).Set("t", Text{Body: "SECRET\r\nline2\n", Max: 100})
	out := finalizeValue(in, true).(*Obj)
	want := map[string]any{"s": "a <redacted>", "v": "SECRET id", "e": "<redacted>", "e2": "/bin",
		"l": "x=<redacted> y", "c": "run  <redacted>", "n": NumText("5"), "b": true, "i32": int32(3), "t": "<redacted>\nline2"}
	for k, w := range want {
		if g, _ := out.Get(k); g != w {
			t.Errorf("%s: %#v want %#v", k, g, w)
		}
	}
	arr, _ := out.Get("arr")
	if a := arr.([]any); a[0] != "<redacted>" || a[1].([]any)[0] != "<redacted>" {
		t.Errorf("arr %#v", a)
	}
	plain := finalizeValue(in, false).(*Obj)
	if g := plain.Str("s"); g != "a SECRET" {
		t.Errorf("no-redact %q", g)
	}
	if g, _ := plain.Get("e"); g != "abc" {
		t.Errorf("no-redact named %q", g)
	}
	if in.Str("s") != "a SECRET" {
		t.Error("input changed")
	}
}

func TestCapText(t *testing.T) {
	installStandIns(t)
	cases := []struct {
		body string
		max  int
		want string
	}{
		{"abc\ndef\n", 7, "abc\ndef"},
		{"abc\ndef\n", 6, "abc\n" + truncMark},
		{"abcdef", 3, truncMark},
		{"a\x00b", 10, noReadText},
		{"\xff\xfea", 10, noReadText},
		{"x\n-----BEGIN PRIVATE KEY-----\n", 3, "x\n-----BEGIN PRIVATE KEY-----"},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := capText(c.body, c.max, true); got != c.want {
			t.Errorf("capText(%q,%d)=%q want %q", c.body, c.max, got, c.want)
		}
	}
	if got := capText("SECRET", 0, false); got != "SECRET" {
		t.Errorf("no redaction: %q", got)
	}
}

func TestEnvelopeAndRaw(t *testing.T) {
	r := newResult("a.b")
	r.Src("read /x")
	r.Note("n1\nn2")
	r.Fail("boom\nmore")
	r.SetRaw("first", strings.Repeat("x", rawMaxBytes-10))
	r.SetRaw("second", strings.Repeat("y", 20))
	r.SetRaw("third", "z")
	rec := &runRecord{Probe: SpecProbe{ID: "a.b", Tier: "default", Scope: "machine", Title: "T"}, Res: r, DurMS: 5}
	o := envelope(rec, false)
	if strings.Join(o.Keys(), ",") != "status,tier,scope,title,sources,duration_ms,data,raw,truncated,error,notes" {
		t.Fatalf("keys %v", o.Keys())
	}
	raw, _ := o.Get("raw")
	if raw.(*Obj).Len() != 2 {
		t.Fatalf("raw %v", raw.(*Obj).Keys())
	}
	if sec, _ := raw.(*Obj).Get("second"); sec.(Text).Max != 10 {
		t.Fatalf("second max %d", sec.(Text).Max)
	}
	if tr, _ := o.Get("truncated"); tr != true {
		t.Fatal("truncated")
	}
	if o.Str("error") != "boom" {
		t.Fatalf("error %q", o.Str("error"))
	}
	if n, _ := o.Get("notes"); len(n.([]any)) != 2 {
		t.Fatal("notes")
	}
	safe := envelope(rec, true)
	if d, _ := safe.Get("data"); d.(*Obj).Len() != 0 || safe.Str("error") == "boom" {
		t.Fatal("safe envelope")
	}
	if _, has := safe.Get("raw"); has {
		t.Fatal("safe raw")
	}
	ok := envelope(&runRecord{Probe: rec.Probe, Res: newResult("a.b")}, false)
	if e, has := ok.Get("error"); !has || e != nil {
		t.Fatal("null error")
	}
	if _, has := ok.Get("notes"); has {
		t.Fatal("notes absent when empty")
	}
}

func TestCountRecords(t *testing.T) {
	mk := func(st, kind string) *runRecord {
		r := newResult("x")
		r.Status = st
		return &runRecord{Res: r, Kind: kind}
	}
	c, exit := countRecords([]*runRecord{mk(StOK, "-"), mk(StNotFound, "-"), mk(StSkipped, "tier")})
	if exit != 0 || c[StOK] != 1 || c[StSkipped] != 1 || c[StError] != 0 {
		t.Fatalf("%v %d", c, exit)
	}
	for _, st := range []string{StPartial, StDenied, StTimeout, StError} {
		if _, exit := countRecords([]*runRecord{mk(st, "-")}); exit != 1 {
			t.Errorf("%s exit", st)
		}
	}
	if _, exit := countRecords([]*runRecord{mk(StSkipped, "budget")}); exit != 1 {
		t.Error("budget exit")
	}
}
