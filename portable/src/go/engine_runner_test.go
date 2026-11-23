package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testProbes() []SpecProbe {
	return []SpecProbe{
		{ID: "t.ok", Title: "ok", Tier: "default", Scope: "machine"},
		{ID: "t.partial", Title: "partial", Tier: "default", Scope: "user"},
		{ID: "t.panic", Title: "panic", Tier: "default", Scope: "machine"},
		{ID: "t.slow", Title: "slow", Tier: "default", Scope: "machine"},
		{ID: "t.deep", Title: "deep", Tier: "deep", Scope: "machine"},
		{ID: "t.net", Title: "net", Tier: "net", Scope: "machine"},
		{ID: "t.missing", Title: "missing", Tier: "default", Scope: "machine"},
		{ID: "t.reader", Title: "reads facts", Tier: "default", Scope: "machine"},
	}
}

func testFuncs(seen map[string]string) map[string]probeFunc {
	return map[string]probeFunc{
		"t.ok":      func(e Env, r *Result) { r.Fact("ok_fact", "1"); r.Data.Set("k", "v") },
		"t.partial": func(e Env, r *Result) { r.Fact("partial_fact", "2"); r.Partial("half") },
		"t.panic":   func(e Env, r *Result) { r.Fact("panic_fact", "3"); panic("bad") },
		"t.slow": func(e Env, r *Result) {
			r.Fact("slow_fact", "4")
			time.Sleep(300 * time.Millisecond)
		},
		"t.deep": func(e Env, r *Result) { r.Fact("deep_fact", "5") },
		"t.net":  func(e Env, r *Result) {},
		"t.reader": func(e Env, r *Result) {
			for _, k := range []string{"ok_fact", "partial_fact", "panic_fact", "slow_fact", "deep_fact", "wsl"} {
				seen[k] = e.Fact(k)
			}
		},
	}
}

func newTestRunner(t *testing.T, o *options, seen map[string]string) (*runner, *bytes.Buffer) {
	e := newTestEnv(t, t.TempDir(), o)
	var errb bytes.Buffer
	rn := newRunner(e, &errb)
	rn.funcs, rn.probes = testFuncs(seen), testProbes()
	rn.capShort = 50 * time.Millisecond
	return rn, &errb
}

func TestRunnerStatusesAndFacts(t *testing.T) {
	seen := map[string]string{}
	rn, errb := newTestRunner(t, nil, seen)
	recs := rn.runAll("/out")
	st := map[string]*runRecord{}
	for _, r := range recs {
		st[r.Probe.ID] = r
	}
	want := map[string]string{"t.ok": StOK, "t.partial": StPartial, "t.panic": StError, "t.slow": StTimeout,
		"t.deep": StSkipped, "t.net": StSkipped, "t.missing": StError, "t.reader": StOK}
	for id, w := range want {
		if st[id].Res.Status != w {
			t.Errorf("%s: %s want %s", id, st[id].Res.Status, w)
		}
	}
	if !strings.Contains(st["t.panic"].Res.Error, "panic: bad") || st["t.missing"].Res.Error != "probe function probe_t_missing is missing" {
		t.Errorf("errors %q %q", st["t.panic"].Res.Error, st["t.missing"].Res.Error)
	}
	if n := st["t.slow"].Res.Notes; len(n) != 1 || n[0] != "probe stopped after 0s (per-probe time cap or scan budget)" {
		t.Errorf("slow notes %v", n)
	}
	if st["t.deep"].Res.Notes[0] != "tier deep is not enabled (use --deep)" || st["t.deep"].Kind != "tier" {
		t.Error("deep skip")
	}
	if seen["ok_fact"] != "1" || seen["partial_fact"] != "2" || seen["panic_fact"] != "" || seen["slow_fact"] != "" ||
		seen["deep_fact"] != "" || seen["wsl"] != "false" {
		t.Errorf("facts %v", seen)
	}
	out := errb.String()
	if !strings.HasPrefix(out, "envscan "+spec.Version+" (go): 8 probes, tiers default -> /out\n") ||
		!regexp.MustCompile(`\[ 1/8\] t\.ok \.{29} ok +[0-9]+ ms\n`).MatchString(out) {
		t.Fatalf("progress:\n%s", out)
	}
}

func TestRunnerSelectionAndBudget(t *testing.T) {
	o := defaultOptions()
	o.Deep, o.Only, o.Skip = true, "t.ok,t.deep,t.partial", "t.partial"
	rn, _ := newTestRunner(t, o, map[string]string{})
	recs := rn.runAll("/o")
	for _, r := range recs {
		switch r.Probe.ID {
		case "t.ok", "t.deep":
			if r.Res.Status != StOK {
				t.Errorf("%s %s", r.Probe.ID, r.Res.Status)
			}
		case "t.net":
			if r.Res.Status != StSkipped || r.Kind != "tier" {
				t.Errorf("net %s", r.Kind)
			}
		case "t.partial":
			if r.Res.Notes[0] != "excluded by --skip" {
				t.Error(r.Res.Notes)
			}
		default:
			if r.Res.Status != StSkipped || r.Kind != "select" {
				t.Errorf("%s %s %s", r.Probe.ID, r.Res.Status, r.Kind)
			}
		}
	}
	o2 := defaultOptions()
	o2.BudgetSec = 1
	rn2, _ := newTestRunner(t, o2, map[string]string{})
	rn2.e.deadline = testClock()
	rec := rn2.runOne(1, rn2.probes[0])
	if rec.Res.Status != StSkipped || rec.Kind != "budget" || rec.Res.Notes[0] != "scan budget of 1s exhausted" {
		t.Fatalf("%+v %v", rec, rec.Res.Notes)
	}
	if c := rn2.capFor(longProbeID, 3); c != 3*time.Second {
		t.Fatal(c)
	}
	rn2.capShort = time.Hour
	if c := rn2.capFor("x", 100000); c != time.Hour {
		t.Fatal(c)
	}
}
