// pb_tools.go: tools.inventory (port of src/sh/25-tools.sh probe_tools_inventory, es_binarch,
// es_versions).
//
// Fact besides the sh ones: tools_tsv, the sh $ES_TMP/tools.tsv that the brief reads ("id TAB
// name TAB cat TAB version TAB path TAB executed TAB reason TAB arch" per found tool).
package main

import (
	"encoding/binary"
	"regexp"
	"strings"
)

func init() {
	registerProbe("tools.inventory", probeToolsInventory)
}

// pbBinArch is sh es_binarch: the machine type of the first bytes of an executable.
func pbBinArch(b []byte) string {
	n := len(b)
	switch {
	case n >= 20 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return pbELFArch(b)
	case n >= 8 && (b[0] == 0xcf || b[0] == 0xce) && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return pbMachoArch(binary.LittleEndian.Uint32(b[4:8]), "macho-")
	case n >= 8 && b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe:
		return pbFatArch(b)
	case n >= 64 && b[0] == 'M' && b[1] == 'Z':
		return pbPEArch(b)
	case n >= 2 && b[0] == '#' && b[1] == '!':
		return "script"
	}
	return "unknown"
}

func pbELFArch(b []byte) string {
	le := b[5] == 1
	m := int(b[18])<<8 | int(b[19])
	if le {
		m = int(b[18]) | int(b[19])<<8
	}
	switch m {
	case 62:
		return "x86_64"
	case 3:
		return "x86"
	case 183:
		return "arm64"
	case 40:
		return "arm"
	case 21:
		if le {
			return "ppc64le"
		}
		return "ppc64"
	case 20:
		return "ppc"
	case 22:
		return "s390x"
	case 243:
		if b[4] == 2 {
			return "riscv64"
		}
		return "riscv32"
	case 43:
		return "sparc64"
	case 2:
		return "sparc"
	case 50:
		return "ia64"
	case 8:
		return "mips"
	}
	return "elf-" + itoa(m)
}

func pbMachoArch(c uint32, other string) string {
	switch c {
	case 16777223:
		return "x86_64"
	case 16777228:
		return "arm64"
	case 7:
		return "x86"
	case 12:
		return "arm"
	}
	if other == "" {
		return "other"
	}
	return other + itoa(int(c))
}

func pbFatArch(b []byte) string {
	nf := binary.BigEndian.Uint32(b[4:8])
	if nf == 0 || nf >= 8 {
		return "java-class"
	}
	l := []string{}
	for k := 0; k < int(nf); k++ {
		o := 8 + 20*k
		if o+3 >= len(b) {
			break
		}
		l = append(l, pbMachoArch(binary.BigEndian.Uint32(b[o:o+4]), ""))
	}
	return "universal(" + strings.Join(l, ",") + ")"
}

func pbPEArch(b []byte) string {
	e := int(b[60]) | int(b[61])<<8 | int(b[62])<<16
	if e+6 >= len(b) || b[e] != 'P' || b[e+1] != 'E' || b[e+2] != 0 || b[e+3] != 0 {
		return "pe"
	}
	switch m := int(b[e+4]) | int(b[e+5])<<8; m {
	case 34404:
		return "x86_64"
	case 332:
		return "x86"
	case 43620:
		return "arm64"
	case 452:
		return "arm"
	default:
		return "pe-" + itoa(m)
	}
}

// pbVersion is one es_versions result: version ("-" when none), line, loader error.
type pbVersion struct {
	Version, Line string
	Loader        bool
	Any           bool // the output had a non-blank line
}

var (
	pbPickedUp  = regexp.MustCompile(`^(NOTE: )?Picked up [A-Za-z_]+:`)
	pbLoaderErr = []string{"error while loading shared libraries", "not found (required by",
		"error loading shared library", "error relocating", "library not loaded", "exec format error",
		"cannot execute binary file"}
)

func pbIsLoaderError(l string) bool {
	l = strings.ToLower(l)
	for _, s := range pbLoaderErr {
		if strings.Contains(l, s) {
			return true
		}
	}
	return strings.Contains(l, "version `") && strings.Contains(l, "not found")
}

// pbVersions is sh es_versions for one command output.
func pbVersions(out string) pbVersion {
	v := pbVersion{Version: "-"}
	errLine, first, vline := "", "", ""
	for i, l := range lines(out) {
		l = strings.ReplaceAll(l, "\t", " ")
		if pbPickedUp.MatchString(l) {
			continue
		}
		if i < 10 && errLine == "" && pbIsLoaderError(l) {
			errLine = l
		}
		if first == "" && strings.TrimSpace(l) != "" {
			first = l
		}
		if i < 10 && vline == "" {
			if m := pbDottedRe.FindString(l); m != "" {
				v.Version, vline = m, l
			}
		}
	}
	v.Any = first != ""
	switch {
	case !v.Any:
		v.Version = "-"
	case errLine != "":
		v.Version, v.Line, v.Loader = "-", errLine, true
	case vline != "":
		v.Line = vline
	default:
		v.Line = first
	}
	return v
}

// pbToolPaths: the executables of a tool on PATH (all matches) and in its install directories.
func pbToolPaths(e Env, sk *pbSkips, t SpecTool) ([]string, bool) {
	paths, onPath := []string{}, false
	for _, x := range t.Exe {
		if all := pbWhichAll(e, x); len(all) > 0 {
			paths, onPath = append(paths, all...), true
		}
	}
	for _, dp := range t.Dirs {
		for _, d := range pbExpand(e, sk, dp) {
			for _, x := range t.Exe {
				if p := d + "/" + x; pbExecFile(e, p) {
					paths = pbAppendOnce(paths, p)
				}
			}
		}
	}
	return paths, onPath
}

type pbToolRow struct {
	t               SpecTool
	path, why, arch string
	paths           []string
	onPath, ran     bool
	ver             pbVersion
}

// pbToolRun runs the version command of a found tool unless it must not run.
func pbToolRun(e Env, r *Result, row *pbToolRow, tmo *[]string) {
	if row.t.Mode == "presence" {
		row.why = "presence only (not executed)"
		return
	}
	if ok, why := e.Runnable(row.path); !ok {
		row.why = why
		return
	}
	c := runPath(e, r, RunOpt{MergeStderr: true}, row.path, row.t.Args...)
	row.ran = true
	if c.TimedOut {
		row.why = "timed out after " + e.Timeout().String()
		*tmo = append(*tmo, row.t.ID)
	}
	row.ver = pbVersions(c.Stdout)
}

func pbToolItem(row *pbToolRow) *Obj {
	o := NewObj().Set("name", row.t.Name).Set("cat", row.t.Cat).Set("found", row.path != "")
	if row.path == "" {
		return o.Set("path", nil).Set("paths", []any{}).Set("on_path", false).Set("version", nil).
			Set("version_line", nil).Set("executed", false).Set("reason", nil).Set("binary_arch", nil)
	}
	ps := []any{}
	for _, p := range row.paths {
		ps = append(ps, p)
	}
	o.Set("path", row.path).Set("paths", ps).Set("on_path", row.onPath)
	o.Set("version", pbNilIf(row.ver.Version, "-"))
	vl := row.ver.Line
	if len(vl) > 200 {
		vl = vl[:200]
	}
	o.Set("version_line", strOrNil(vl)).Set("executed", row.ran)
	o.Set("reason", strOrNil(row.reason())).Set("binary_arch", strOrNil(row.arch))
	return o
}

func (row *pbToolRow) reason() string {
	if row.ver.Loader {
		return "fails to run: the program could not start (see version_line)"
	}
	return row.why
}

func pbNilIf(s, none string) any {
	if s == none || s == "" {
		return nil
	}
	return s
}

func pbToolOSOK(os string) bool { return os == "all" || os == "unix" || os == "linux" }

func probeToolsInventory(e Env, r *Result) {
	sk := &pbSkips{}
	r.Src("test PATH directories and the known install directories in spec/tools.toml")
	r.Src("read the first 512 bytes of each found executable (ELF/Mach-O/PE machine type)")
	tools, rows, tmo, found := NewObj(), []string{}, []string{}, 0
	for _, t := range spec.Tools {
		if !pbToolOSOK(t.OS) {
			continue
		}
		row := &pbToolRow{t: t, ver: pbVersion{Version: "-"}}
		row.paths, row.onPath = pbToolPaths(e, sk, t)
		if len(row.paths) > 0 {
			row.path = row.paths[0]
			pbToolRun(e, r, row, &tmo)
			if b, _, err := e.ReadFile(row.path, 512); err == nil {
				row.arch = pbBinArch(b)
			}
			found++
			rows = append(rows, strings.Join([]string{t.ID, t.Name, t.Cat, strings.Trim(row.ver.Version, "-"),
				row.path, pbBool(row.ran), row.reason(), row.arch}, "\t"))
		}
		tools.Set(t.ID, pbToolItem(row))
	}
	r.Data.Set("tools", tools).Set("found_count", found)
	if len(tmo) > 0 {
		r.Partial("version command timed out: " + strings.Join(tmo, " "))
	}
	sk.note(r)
	pbToolFacts(e, r, rows)
}

func pbToolFacts(e Env, r *Result, rows []string) {
	shims, mism := 0, []string{}
	osArch := e.Fact("os_arch")
	if osArch == "" {
		osArch = e.Arch()
	}
	known := " x86_64 x86 arm64 arm ppc64le ppc64 s390x riscv64 "
	for _, row := range rows {
		f := strings.Split(row, "\t")
		if strings.Contains(f[6], "shim") {
			shims++
		}
		if f[2] == "runtime" && f[7] != "" && strings.Contains(known, " "+f[7]+" ") && f[7] != osArch {
			mism = append(mism, f[0]+"="+f[7])
		}
	}
	r.Fact("tools_found", itoa(len(rows)))
	r.Fact("shims_skipped", itoa(shims))
	r.Fact("arch_mismatch", strings.Join(mism, ", "))
	r.Fact("tools_tsv", pbLines(rows))
}
