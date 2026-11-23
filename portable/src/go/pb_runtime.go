// pb_runtime.go: runtime.version_managers, runtime.dotnet and runtime.python (port of
// src/sh/25-tools.sh and es_shim_of of src/sh/11-policy.sh, Linux branches).
package main

import (
	"strings"
)

func init() {
	registerProbe("runtime.version_managers", probeRuntimeVersionManagers)
	registerProbe("runtime.dotnet", probeRuntimeDotnet)
	registerProbe("runtime.python", probeRuntimePython)
}

// pbNormDir is sh es_normdir: repeated "/" collapsed, trailing "/" removed.
func pbNormDir(d string) string {
	for strings.Contains(d, "//") {
		d = strings.ReplaceAll(d, "//", "/")
	}
	for len(d) > 1 && strings.HasSuffix(d, "/") {
		d = strings.TrimSuffix(d, "/")
	}
	return d
}

// pbShimOf is sh es_shim_of: the version manager whose marker the lower-cased directory holds
// (and whose required executable is in it, when the manager names one); "" when none.
func pbShimOf(e Env, dir string) string {
	sd := pbNormDir(dir)
	lc := strings.ToLower(sd)
	for _, vm := range spec.VManagers {
		for _, mk := range vm.Markers {
			if mk == "" || !strings.Contains(lc, strings.ToLower(mk)) {
				continue
			}
			if q := vm.Requires; q != "" && q != "-" {
				if !pbLocalExec(e, sd+"/"+q) && !pbLocalExec(e, sd+"/"+q+".exe") {
					continue
				}
			}
			return vm.ID
		}
	}
	return ""
}

func pbLocalExec(e Env, p string) bool { return pbLocal(e, nil, p) && pbExecFile(e, p) }

// pbShimDirs is sh ES_SHIM_DIRS: the PATH entries that are shim directories ([dir, id]).
func pbShimDirs(e Env) [][2]string {
	out, seen := [][2]string{}, map[string]bool{}
	for _, d := range pbPathDirs(e) {
		id := pbShimOf(e, d)
		nd := pbNormDir(d)
		if id == "" || seen[nd] {
			continue
		}
		seen[nd] = true
		out = append(out, [2]string{nd, id})
	}
	return out
}

// pbTailComponents is sh es_tail_components: the last N components of P, N = the components of
// PATTERN that hold a "*" (at least 1).
func pbTailComponents(pattern, p string) string {
	n := 0
	for _, c := range strings.Split(pattern, "/") {
		if strings.Contains(c, "*") {
			n++
		}
	}
	if n == 0 {
		n = 1
	}
	parts := strings.Split(strings.TrimSuffix(p, "/"), "/")
	if n > len(parts) {
		n = len(parts)
	}
	return strings.Join(parts[len(parts)-n:], "/")
}

func probeRuntimeVersionManagers(e Env, r *Result) {
	sk := &pbSkips{}
	r.Src("list the version directories in spec/tools.toml (no shim is executed)")
	r.Src("PATH entries matching version-manager shim directories")
	shimDirs := pbShimDirs(e)
	items := []any{}
	for _, vm := range spec.VManagers {
		shims, vers := []string{}, []string{}
		for _, sd := range shimDirs {
			if sd[1] == vm.ID {
				shims = append(shims, sd[0])
			}
		}
		for _, vp := range vm.Versions {
			for _, d := range pbExpand(e, sk, vp) {
				if pbIsDir(e, d) {
					vers = pbAppendOnce(vers, pbTailComponents(vp, d))
				}
			}
		}
		if len(shims)+len(vers) == 0 {
			continue
		}
		items = append(items, NewObj().Set("id", vm.ID).Set("name", vm.Name).
			Set("shim_dirs", pbList(pbLines(shims))).Set("versions", pbList(pbLines(vers))))
	}
	r.Data.Set("managers", items)
	sk.note(r)
	if len(items) == 0 {
		r.SetStatus(StNotFound, "")
	}
	r.Fact("vmanagers", itoa(len(items)))
}

// pbDotnetFind: dotnet on PATH, else in DOTNET_ROOT and the known directories.
func pbDotnetFind(e Env, sk *pbSkips) string {
	if p, ok := e.Which("dotnet"); ok {
		return p
	}
	root, _ := e.Getenv("DOTNET_ROOT")
	home := e.Home()
	if home != "" {
		home += "/.dotnet"
	}
	for _, d := range []string{root, "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", home, "/opt/dotnet"} {
		if d != "" && pbLocal(e, sk, d+"/dotnet") && pbExecFile(e, d+"/dotnet") {
			return d + "/dotnet"
		}
	}
	return ""
}

func pbFirstFields(out string, n int) string {
	rows := []string{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) == 0 {
			rows = append(rows, "")
			continue
		}
		if len(f) > n {
			f = f[:n]
		}
		rows = append(rows, strings.Join(f, " "))
	}
	return strings.Join(rows, "\n")
}

// pbDotnetDirs reads the SDK and runtime versions from the install directory (dotnet not run).
func pbDotnetDirs(e Env, r *Result, sk *pbSkips, dn string) (string, string) {
	root := pbDir(pbRealpath(e, dn))
	r.Src("list %s/sdk, %s/shared", root, root)
	sdks, rts := []string{}, []string{}
	for _, d := range pbGlob(e, sk, root+"/sdk/*") {
		if pbIsDir(e, d) {
			sdks = append(sdks, pbBase(d))
		}
	}
	for _, d := range pbGlob(e, sk, root+"/shared/*/*") {
		if pbIsDir(e, d) {
			rts = append(rts, pbBase(pbDir(d))+" "+pbBase(d))
		}
	}
	return pbLines(sdks), pbLines(rts)
}

func probeRuntimeDotnet(e Env, r *Result) {
	sk := &pbSkips{}
	defer sk.note(r)
	dn := pbDotnetFind(e, sk)
	r.Data.Set("framework", nil)
	if dn == "" {
		r.Data.Set("sdks", []any{}).Set("runtimes", []any{})
		r.SetStatus(StNotFound, "")
		return
	}
	r.Data.Set("dotnet", dn)
	sdks, rts := "", ""
	if ok, why := e.Runnable(dn); ok {
		if c := runPath(e, r, RunOpt{}, dn, "--list-sdks"); c.Exit == 0 {
			sdks = pbFirstFields(c.Stdout, 1)
		}
		if c := runPath(e, r, RunOpt{}, dn, "--list-runtimes"); c.Exit == 0 {
			rts = pbFirstFields(c.Stdout, 2)
		}
	} else {
		r.Note("%s: %s; versions read from the install directory", dn, why)
		sdks, rts = pbDotnetDirs(e, r, sk, dn)
	}
	r.Data.Set("sdks", pbList(sdks)).Set("runtimes", pbList(rts))
	r.Fact("dotnet_sdks", sdks)
}

// pbPythonCands is sh es_python_cands.
func pbPythonCands(e Env, sk *pbSkips) []string {
	out := []string{}
	for _, n := range []string{"python3", "python", "python2"} {
		out = append(out, pbWhichAll(e, n)...)
	}
	for _, d := range pbPathDirs(e) {
		for _, pat := range []string{d + "/python3.[0-9]", d + "/python3.[0-9][0-9]"} {
			ms, _ := e.Glob(pat)
			for _, f := range ms {
				if pbExecFile(e, f) {
					out = append(out, f)
				}
			}
		}
	}
	for _, f := range []string{"/usr/libexec/platform-python", "/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"} {
		if pbLocal(e, sk, f) && pbExecFile(e, f) {
			out = append(out, f)
		}
	}
	return out
}

func pbIsStoreAlias(p string) bool {
	return strings.Contains(strings.ToLower(p), "/microsoft/windowsapps/")
}

func probeRuntimePython(e Env, r *Result) {
	sk := &pbSkips{}
	r.Src("test PATH and known locations for python3/python")
	items, seen, vers := []any{}, map[string]bool{}, []string{}
	for _, p := range pbPythonCands(e, sk) {
		rp := pbRealpath(e, p)
		if seen[rp] {
			continue
		}
		seen[rp] = true
		ver, why := "", ""
		if ok, w := e.Runnable(p); ok {
			c := runPath(e, r, RunOpt{MergeStderr: true}, p, "--version")
			if c.Exit == 0 && c.Stdout != "" {
				ver = pbVersionOf(pbFirstLine(c.Stdout))
			}
		} else {
			why = w
		}
		items = append(items, NewObj().Set("path", p).Set("real_path", strOrNil(rp)).Set("version", strOrNil(ver)).
			Set("store_alias", pbIsStoreAlias(p)).Set("not_run_reason", strOrNil(why)))
		v := ver
		if v == "" {
			v = "unknown"
		}
		if why != "" {
			v += " (not run)"
		}
		vers = append(vers, v)
	}
	r.Data.Set("interpreters", items).Set("launcher", []any{})
	sk.note(r)
	if len(items) == 0 {
		r.SetStatus(StNotFound, "")
		r.Fact("python_found", "false")
	} else {
		r.Fact("python_found", "true")
	}
	r.Fact("python_versions", pbLines(vers))
}
