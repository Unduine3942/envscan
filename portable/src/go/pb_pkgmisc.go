// pb_pkgmisc.go: pkg.caches and pkg.installed (port of src/sh/24-pkg.sh, Linux branches).
package main

import (
	"sort"
	"strings"
)

func init() {
	registerProbe("pkg.caches", probePkgCaches)
	registerProbe("pkg.installed", probePkgInstalled)
}

// pbCacheCap is sh ES_CACHE_CAP (a variable so that the tests can lower it).
var pbCacheCap = 10000

func probePkgCaches(e Env, r *Result) {
	sk := &pbSkips{}
	r.Src("list cache directories from spec/configs.toml (top-level entry counts, at most %d per directory)", pbCacheCap)
	items, found, ntr := []any{}, []string{}, 0
	for _, c := range spec.Caches {
		for _, pat := range c.Paths {
			for _, d := range pbExpand(e, sk, pat) {
				if !pbIsDir(e, d) {
					continue
				}
				ents, _, err := e.ReadDir(d, pbCacheCap+1)
				if err != nil || len(ents) == 0 {
					continue
				}
				cnt, tr := len(ents), false
				if cnt > pbCacheCap {
					cnt, tr = pbCacheCap, true
					ntr++
				}
				items = append(items, NewObj().Set("id", c.ID).Set("tool", c.Tool).Set("path", d).
					Set("entries", num(itoa(cnt))).Set("truncated", tr))
				found = append(found, c.ID)
			}
		}
	}
	r.Data.Set("caches", items)
	if ntr > 0 {
		r.Truncated = true
		r.Note("entries are counted up to %d per directory; %d cache directories hold more (truncated)", pbCacheCap, ntr)
	}
	sk.note(r)
	if len(found) == 0 {
		r.SetStatus(StNotFound, "")
	}
	r.Fact("caches", pbLines(found))
}

// pbPkg is one installed package (manager, name, version).
type pbPkg struct{ M, Name, Ver string }

var pbApkVer = pbLongest(`-[0-9][^-]*(-r[0-9]+)?(_[0-9]+)?(,[0-9]+)?$`)

// pbPkgList is sh es_pkg_list for the Linux formats (tab, space, apk).
func pbPkgList(m, format, out string) []pbPkg {
	ps := []pbPkg{}
	for _, l := range lines(out) {
		if strings.TrimSpace(l) == "" {
			continue
		}
		switch format {
		case "tab":
			a := strings.Split(l, "\t")
			a = append(a, "")
			ps = append(ps, pbPkg{m, a[0], a[1]})
		case "space":
			f := append(strings.Fields(l), "")
			ps = append(ps, pbPkg{m, f[0], f[1]})
		case "apk":
			s := strings.Fields(l)[0]
			if loc := pbApkVer.FindStringIndex(s); loc != nil {
				ps = append(ps, pbPkg{m, s[:loc[0]], s[loc[0]+1:]})
			} else {
				ps = append(ps, pbPkg{m, s, ""})
			}
		}
	}
	return ps
}

var pbPkgManagers = []struct {
	name, format string
	args         []string
}{
	{"dpkg-query", "tab", []string{"-W", `-f=${Package}\t${Version}\n`}},
	{"rpm", "tab", []string{"-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\n`}},
	{"apk", "apk", []string{"info", "-v"}},
	{"pacman", "space", []string{"-Q"}},
	{"brew", "space", []string{"list", "--versions"}},
}

func pbMgrID(name string) string {
	if name == "dpkg-query" {
		return "dpkg"
	}
	return name
}

func probePkgInstalled(e Env, r *Result) {
	all, mgrs := []pbPkg{}, []string{}
	managers := []any{}
	for _, pm := range pbPkgManagers {
		c, ok := needTool(e, r, RunOpt{}, pm.name, pm.args...)
		if !ok {
			continue
		}
		id := pbMgrID(pm.name)
		ps := pbPkgList(id, pm.format, c.Stdout)
		all = append(all, ps...)
		mgrs = append(mgrs, id)
		managers = append(managers, NewObj().Set("name", id).Set("count", num(itoa(len(ps)))))
	}
	sorted := append([]pbPkg(nil), all...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].M+"\t"+sorted[i].Name+"\t"+sorted[i].Ver < sorted[j].M+"\t"+sorted[j].Name+"\t"+sorted[j].Ver
	})
	pkgs := []any{}
	for i, p := range sorted {
		if i >= 500 {
			break
		}
		pkgs = append(pkgs, NewObj().Set("name", p.Name).Set("version", p.Ver).Set("source", p.M))
	}
	trunc := len(all) > 500
	r.Data.Set("managers", managers).Set("packages", pkgs).Set("total", num(itoa(len(all)))).Set("truncated", trunc)
	if trunc {
		r.Truncated = true
	}
	if len(mgrs) == 0 {
		r.SetStatus(StNotFound, "no supported package manager was found")
	}
	r.Fact("pkg_managers", strings.Join(mgrs, " "))
	r.Fact("pkg_total", itoa(len(all)))
}
