// report_md_test.go: envscan.md layout (port of es_render_md + json.awk mode md).
package main

import (
	"fmt"
	"strings"
	"testing"
)

func list(items ...any) []any { return items }

func mdTestFinding(id, sev, title, detail, rec string, ev ...any) *Obj {
	return NewObj().Set("id", id).Set("severity", sev).Set("title", title).Set("detail", detail).
		Set("recommendation", rec).Set("evidence", ev)
}

func mdTestProbe(status, title string, dur int, sources []any, data, raw *Obj, errText any, notes []any) *Obj {
	p := NewObj().Set("status", status).Set("tier", "default").Set("scope", "system").Set("title", title).
		Set("sources", sources).Set("duration_ms", dur).Set("data", data)
	if raw != nil {
		p.Set("raw", raw)
	}
	p.Set("truncated", false).Set("error", errText)
	if notes != nil {
		p.Set("notes", notes)
	}
	return p
}

func mdTestDoc() *Obj {
	long := []any{}
	for i := 1; i <= 15; i++ {
		long = append(long, fmt.Sprintf("item-%05d", i))
	}
	data := NewObj().
		Set("name", "Ubuntu").
		Set("ids", list("a", "b")).
		Set("empty", []any{}).
		Set("nested", NewObj().Set("k", Verbatim("v")).Set("deep", NewObj().Set("x", 1))).
		Set("flag", true).
		Set("none", nil).
		Set("blank", "").
		Set("objs", list(NewObj().Set("a", NumText("1")), NewObj().Set("b", int64(2)))).
		Set("pipes", "a|b\nc\td\r").
		Set("mixed", list("s1", NewObj().Set("c", 3), "s2")).
		Set("long", long).
		Set("big", strings.Repeat("x", 305)).
		Set("bytes", "caf\xc3\xa9 \xff\x01").
		Set("lists", list(list("p", "q"), list())).
		Set("nest2", list(list("x", NewObj().Set("y", 1))))
	raw := NewObj().Set("uname", Text{Body: "Linux box1\r\n```x```\n"})
	probes := NewObj().
		Set("os.identity", mdTestProbe("ok", "Operating system", 3, list("read /etc/os-release", "run uname -a"),
			data, raw, nil, list("note one"))).
		Set("hw.gpu", mdTestProbe("partial", "GPU", 5, list(), NewObj(), NewObj(), "lspci failed\nsecond", list("n1", "n2"))).
		Set("net.dns", mdTestProbe("skipped", "DNS", 0, list(), NewObj(), nil, nil, list("not selected by --only")))
	counts := NewObj()
	for _, s := range []string{"ok", "partial", "not_found", "not_applicable", "denied", "timeout", "error", "skipped"} {
		counts.Set(s, 0)
	}
	counts.Set("ok", 1).Set("partial", 1).Set("skipped", 1)
	return NewObj().
		Set("schema", "envscan/1").
		Set("scanner", NewObj().Set("name", "envscan").Set("version", "1.0.0").Set("impl", "go").Set("shell_version", "go1.27.4")).
		Set("run", NewObj().Set("started_utc", "2026-11-14T10:00:00Z").Set("finished_utc", "2026-11-14T10:00:09Z").
			Set("duration_ms", 9000).Set("tiers", list("default", "deep")).Set("flags", list()).Set("cwd", "/").
			Set("out_dir", "/tmp/o").Set("exit_code", 1).Set("redaction", true).Set("counts", counts)).
		Set("host", NewObj().Set("os_family", "linux").Set("os_name", "Ubuntu").Set("os_version", "24.04").
			Set("arch", "x86_64").Set("hostname", "box1")).
		Set("findings", list(
			mdTestFinding("os.pending_reboot", "warning", "Reboot pending", "kernel", "Reboot first.", "os.health"),
			mdTestFinding("user.is_admin", "info", "Running as root", "uid 0 (root)", "Mind it.", "user.identity", "x.y"))).
		Set("probes", probes)
}

func TestRenderMarkdownLayout(t *testing.T) {
	want := []string{
		"# envscan report: box1",
		"",
		"- envscan 1.0.0 (go, go1.27.4), started 2026-11-14T10:00:00Z, finished 2026-11-14T10:00:09Z",
		"- tiers: default, deep; redaction: on; exit code 1",
		"- probes: 3 (1 ok, 1 partial, 0 not_found, 0 not_applicable, 0 denied, 0 timeout, 0 error, 1 skipped)",
		"",
		"## Findings",
		"",
		"- **[warning] Reboot pending** (os.pending_reboot): kernel",
		"  - recommendation: Reboot first.",
		"  - evidence: os.health",
		"- **[info] Running as root** (user.is_admin): uid 0 (root)",
		"  - recommendation: Mind it.",
		"  - evidence: user.identity, x.y",
		"",
		"## os.identity - Operating system",
		"",
		"- status: **ok** - tier default - scope system - 3 ms",
		"- sources: read /etc/os-release; run uname -a",
		"- note: note one",
		"",
		"- name: Ubuntu",
		"- ids: a, b",
		"- empty: (none)",
		"- nested:",
		"  - k: v",
		"  - deep:",
		"    - x: 1",
		"- flag: true",
		"- none: null",
		"- blank: \"\"",
		"- objs:",
		"  - (1)",
		"    - a: 1",
		"  - (2)",
		"    - b: 2",
		"- pipes: a/b / c d",
		"- mixed:",
		"  - s1",
		"  - (1)",
		"    - c: 3",
		"  - s2",
		"- long:",
	}
	for i := 1; i <= 14; i++ {
		want = append(want, fmt.Sprintf("  - item-%05d", i))
	}
	want = append(want,
		"  - item-00015",
		"- big: "+strings.Repeat("x", 300)+"...",
		"- bytes: caf\xc3\xa9 ? ",
		"- lists:",
		"  - p, q",
		"  - (none)",
		"- nest2:",
		"  - (list)",
		"    - x",
		"    - (1)",
		"      - y: 1",
		"",
		"raw output `uname`:",
		"",
		"```text",
		"Linux box1",
		"'''x'''",
		"```",
		"",
		"",
		"## hw.gpu - GPU",
		"",
		"- status: **partial** - tier default - scope system - 5 ms",
		"- error: lspci failed",
		"- note: n1",
		"- note: n2",
		"",
		"## net.dns - DNS",
		"",
		"- status: **skipped** - tier default - scope system - 0 ms",
		"- note: not selected by --only",
	)
	got := renderMarkdown(mdTestDoc())
	compareLines(t, got, want)
}

func compareLines(t *testing.T, got string, want []string) {
	t.Helper()
	exp := strings.Join(want, "\n") + "\n"
	if got == exp {
		return
	}
	g := strings.Split(got, "\n")
	for i := range want {
		if i >= len(g) || g[i] != want[i] {
			gl := "<eof>"
			if i < len(g) {
				gl = g[i]
			}
			t.Fatalf("line %d:\n got %q\nwant %q\n--- full output:\n%s", i+1, gl, want[i], got)
		}
	}
	t.Fatalf("extra output after line %d:\n%s", len(want), got)
}

func TestRenderMarkdownNoFindingsNoRedaction(t *testing.T) {
	doc := mdTestDoc()
	doc.Set("findings", []any{})
	run, _ := doc.Get("run")
	run.(*Obj).Set("redaction", false).Set("test_root", "/fx")
	got := renderMarkdown(doc)
	for _, s := range []string{"redaction: off; exit code 1\n", "\n- test root (ENVSCAN_ROOT): /fx\n", "## Findings\n\n- none\n"} {
		if !strings.Contains(got, s) {
			t.Fatalf("missing %q in\n%s", s, got)
		}
	}
}

func TestRenderMarkdownRawText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"a\nb\n", "a\nb"},
		{"aaaa\nbbbb\ncccc", "aaaa\nbbbb\n[... truncated]"},
		{"toolongline", "[... truncated]"},
		{"x\r\n\xff", "x\n?"},
	}
	for _, c := range cases {
		if got := mdRawText(c.in, 10); got != c.want {
			t.Fatalf("mdRawText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRenderU8Clean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"tab\there\x7f", "tab here "},
		{"\xe2\x82\xac ok", "\xe2\x82\xac ok"},
		{"\xed\xa0\x80", "???"},
		{"\xc2\x85", "\xc2\x85"},
		{"\xf0\x9f\x98", "???"},
	}
	for _, c := range cases {
		if got := u8clean(c.in); got != c.want {
			t.Fatalf("u8clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := mdClean(strings.Repeat("a", 299) + "\xc3\xa9b"); got != strings.Repeat("a", 299)+"..." {
		t.Fatalf("mdClean cut %q", got)
	}
}
