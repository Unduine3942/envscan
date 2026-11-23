package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var pbELF64 = func() string {
	b := make([]byte, 64)
	copy(b, "\x7fELF\x02\x01\x01")
	b[18], b[19] = 183, 0 // aarch64
	return string(b)
}()

func pbToolSpec(d *SpecDoc) {
	d.Tools = []SpecTool{
		{ID: "node", Name: "Node.js", Cat: "runtime", Mode: "version", OS: "all", Exe: []string{"node"}, Args: []string{"--version"}, Dirs: []string{"/usr/local/bin"}},
		{ID: "bun", Name: "Bun", Cat: "runtime", Mode: "version", OS: "all", Exe: []string{"bun"}, Args: []string{"--version"}, Dirs: []string{"~/.bun/bin"}},
		{ID: "rustc", Name: "Rust compiler", Cat: "runtime", Mode: "version", OS: "all", Exe: []string{"rustc"}, Args: []string{"--version"}, Dirs: []string{"~/.cargo/bin"}},
		{ID: "terraform", Name: "Terraform", Cat: "iac", Mode: "presence", OS: "linux", Exe: []string{"terraform"}},
		{ID: "slow", Name: "Slow", Cat: "dev", Mode: "version", OS: "unix", Exe: []string{"slow"}, Args: []string{"-v"}},
		{ID: "macos", Name: "Mac", Cat: "dev", Mode: "version", OS: "darwin", Exe: []string{"node"}},
		{ID: "absent", Name: "Absent", Cat: "dev", Mode: "version", OS: "all", Exe: []string{"absent"}},
	}
}

func TestToolsInventory(t *testing.T) {
	e := pbNewEnv(t)
	pbSwapSpec(t, pbToolSpec)
	e.Vars["PATH"] = "/usr/bin:/opt/bin:relative"
	pbWrite(t, e.Root, map[string]string{
		"/usr/bin/node": pbELF64, "/opt/bin/node": "#!/bin/sh\n", "/usr/local/bin/node": "x",
		"/home/u/.bun/bin/bun": "#!/bin/sh\n", "/home/u/.cargo/bin/rustc": "x", "/usr/bin/terraform": "x", "/usr/bin/slow": "x",
	})
	e.NoRun["/home/u/.cargo/bin/rustc"] = "version-manager shim (rustup, not executed)"
	e.Cmds["node --version"] = fakeCmd{Stderr: "node: error while loading shared libraries: libnode.so.108: cannot open shared object file\n", Exit: 127}
	e.Cmds["bun --version"] = fakeCmd{Stderr: "Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8\n", Stdout: "1.1.30\n"}
	e.Cmds["slow -v"] = fakeCmd{TimedOut: true, Exit: 124}
	e.FactsIn["os_arch"] = "x86_64"
	r := pbRun(e, "tools.inventory")
	tools := pbGet(t, r.Data, "tools").(*Obj)
	pbEq(t, "ids", tools.Keys(), []string{"node", "bun", "rustc", "terraform", "slow", "absent"})
	node := tools.vals["node"].(*Obj)
	pbKeys(t, node, "name", "cat", "found", "path", "paths", "on_path", "version", "version_line", "executed", "reason", "binary_arch")
	pbEq(t, "node paths", pbStrs(node.vals["paths"]), []string{"/usr/bin/node", "/opt/bin/node", "/usr/local/bin/node"})
	pbEq(t, "node version", node.vals["version"], nil)
	if !strings.HasPrefix(node.Str("reason"), "fails to run") || !strings.Contains(node.Str("version_line"), "error while loading shared libraries") {
		t.Errorf("node %v", node.vals)
	}
	pbEq(t, "node arch", node.Str("binary_arch"), "arm64")
	bun := tools.vals["bun"].(*Obj)
	pbEq(t, "bun", []any{bun.Str("version"), bun.vals["on_path"], bun.Str("binary_arch")}, []any{"1.1.30", false, "script"})
	rust := tools.vals["rustc"].(*Obj)
	pbEq(t, "rustc", []any{rust.vals["found"], rust.vals["executed"], rust.Str("reason")},
		[]any{true, false, "version-manager shim (rustup, not executed)"})
	pbEq(t, "terraform", tools.vals["terraform"].(*Obj).Str("reason"), "presence only (not executed)")
	pbEq(t, "slow", tools.vals["slow"].(*Obj).Str("reason"), "timed out after 10s")
	abs := tools.vals["absent"].(*Obj)
	pbEq(t, "absent", []any{abs.vals["found"], abs.vals["paths"], abs.vals["executed"]}, []any{false, []any{}, false})
	pbEq(t, "found_count", r.Data.vals["found_count"], 5)
	pbEq(t, "status", r.Status, StPartial)
	if !pbHasNote(r, "version command timed out: slow") || pbRan(e, "rustc") || pbRan(e, "terraform") {
		t.Errorf("notes %v ran %v", r.Notes, e.Ran)
	}
	pbEq(t, "facts", []string{r.Facts["tools_found"], r.Facts["shims_skipped"], r.Facts["arch_mismatch"]},
		[]string{"5", "1", "node=arm64"})
	if !strings.Contains(r.Facts["tools_tsv"], "bun\tBun\truntime\t1.1.30\t/home/u/.bun/bin/bun\ttrue\t\tscript\n") {
		t.Errorf("tsv %q", r.Facts["tools_tsv"])
	}
}

func TestToolsInventoryNetworkPathAndDistroless(t *testing.T) {
	e := pbNewEnv(t)
	pbSwapSpec(t, pbToolSpec)
	e.Vars["PATH"] = "/nethome/bin:/usr/bin"
	e.NetPaths = []string{"/nethome"}
	e.Vars["HOME"] = "/nethome"
	pbWrite(t, e.Root, map[string]string{"/nethome/bin/node": "x", "/nethome/.bun/bin/bun": "x"})
	r := pbRun(e, "tools.inventory")
	tools := r.Data.vals["tools"].(*Obj)
	pbEq(t, "node", tools.vals["node"].(*Obj).vals["found"], false)
	pbEq(t, "ran", len(e.Ran), 0)
	if !pbHasNote(r, "/nethome/.bun/bin") {
		t.Errorf("notes %v", r.Notes)
	}
	empty := pbNewEnv(t)
	r = pbRun(empty, "tools.inventory")
	pbEq(t, "distroless", []any{r.Status, r.Data.vals["found_count"]}, []any{StOK, 0})
}

func TestBinArch(t *testing.T) {
	elf := func(class, data byte, m uint16) []byte {
		b := make([]byte, 64)
		copy(b, "\x7fELF")
		b[4], b[5] = class, data
		if data == 1 {
			b[18], b[19] = byte(m), byte(m>>8)
		} else {
			b[18], b[19] = byte(m>>8), byte(m)
		}
		return b
	}
	pe := make([]byte, 200)
	copy(pe, "MZ")
	pe[60] = 128
	copy(pe[128:], "PE\x00\x00\x64\x86")
	macho := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}
	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0x01, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x0c}
	cases := map[string][]byte{
		"x86_64": elf(2, 1, 62), "ppc64le": elf(2, 1, 21), "ppc64": elf(2, 2, 21), "s390x": elf(2, 2, 22),
		"riscv64": elf(2, 1, 243), "elf-999": elf(2, 1, 999), "arm64": macho, "universal(x86_64,arm64)": fat,
		"java-class": {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52}, "pe": append([]byte("MZ"), make([]byte, 62)...),
		"script": []byte("#!/bin/sh"), "unknown": []byte("hello"),
	}
	cases["x86_64 "] = pe
	for want, b := range cases {
		pbEq(t, want, pbBinArch(b), strings.TrimSpace(want))
	}
}

// TestVersionsCommandsJSON: es_versions on the captured outputs of tests/data/commands.json.
func TestVersionsCommandsJSON(t *testing.T) {
	b, err := os.ReadFile("../../tests/data/commands.json")
	if err != nil {
		t.Skip("tests/data/commands.json not found")
	}
	var doc struct {
		Groups map[string][]struct {
			Name, Output string
			Facts        map[string]any
		} `json:"groups"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Groups["versions"] {
		v := pbVersions(c.Output)
		status := "-"
		if v.Loader {
			status = "loader"
		}
		pbEq(t, c.Name, []string{v.Version, v.Line, status}, []string{c.Facts["version"].(string), c.Facts["line"].(string), c.Facts["status"].(string)})
	}
	for _, c := range doc.Groups["arch"] {
		pbEq(t, c.Name, pbNormArch(strings.TrimSpace(c.Output)), c.Facts["arch"].(string))
	}
}
