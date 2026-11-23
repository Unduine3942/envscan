package main

import "testing"

func TestNumMatchesJsonAwk(t *testing.T) {
	cases := map[string]any{"": nil, "007": NumText("7"), "-0": NumText("0"), "1.50": NumText("1.50"),
		"0.5": NumText("0.5"), "1e5": "1e5", "-": "-", "12a": "12a", ".5": ".5", "5.": "5."}
	for in, want := range cases {
		if got := num(in); got != want {
			t.Errorf("num(%q) = %#v, want %#v", in, got, want)
		}
	}
}

func TestObjKeepsFirstPositionLastValue(t *testing.T) {
	o := NewObj().Set("a", 1).Set("b", 2).Set("a", 3)
	if k := o.Keys(); len(k) != 2 || k[0] != "a" || k[1] != "b" {
		t.Fatalf("keys %v", k)
	}
	if v, _ := o.Get("a"); v != 3 {
		t.Fatalf("a = %v", v)
	}
}

func TestReadTextFromFixture(t *testing.T) {
	e := newFakeEnv(t, fixtureRoot(t, "linux-basic"))
	r := newResult("x")
	text, ok := readText(e, r, "/etc/os-release", 0)
	if !ok || text == "" || r.Sources[0] != "read /etc/os-release" {
		t.Fatalf("ok=%v sources=%v", ok, r.Sources)
	}
	e.RefusedP["/etc"] = "credential store"
	r2 := newResult("y")
	if _, ok := readText(e, r2, "/etc/os-release", 0); ok || len(r2.Notes) != 1 || len(r2.Sources) != 0 {
		t.Fatalf("refused read: ok=%v notes=%v sources=%v", ok, r2.Notes, r2.Sources)
	}
}
