// engine_glob.go: Glob, a port of es_glob / es_glob_take. A pattern that names a credential
// store is never expanded; a glob whose base folder is on (or has below it) a network or autofs
// mount is skipped; the pattern is expanded one globbed component at a time and every folder
// and result is vetted before it is used. What was left out is reported to skipRec (the runner
// turns it into the probe notes, like es_netskip_note).
package main

import (
	"os"
	"path"
	"strings"
)

// skipRec receives a path left out (credLink: a link into a credential store, else a network
// or autofs mount).
type skipRec func(p string, credLink bool)

func (e *realEnv) Glob(pattern string) ([]string, error) { return e.globRec(pattern, nil) }

func (e *realEnv) globRec(pattern string, rec skipRec) ([]string, error) {
	if rec == nil {
		rec = func(string, bool) {}
	}
	if !strings.HasPrefix(pattern, "/") || credPath(pattern) {
		return nil, nil
	}
	if i := indexMeta(pattern); i >= 0 {
		base := parentOf(pattern[:i])
		if why := e.rv.refusedWhy(base); why != "" || netmntUnder(base, e.rv.netmnts) {
			rec(pattern, why == whyCredLink)
			return nil, nil
		}
	}
	g := &globber{e: e, rec: rec}
	todo := []string{pattern}
	for len(todo) > 0 {
		q := todo[0]
		todo = todo[1:]
		todo = append(todo, g.step(q)...)
	}
	return sortedUnique(g.out), nil
}

type globber struct {
	e   *realEnv
	rec skipRec
	out []string
}

// step expands the first globbed component of q; it returns the patterns still to expand.
func (g *globber) step(q string) []string {
	i := indexMeta(q)
	if i < 0 {
		g.take(q)
		return nil
	}
	dir := parentOf(q[:i])
	tail := strings.TrimPrefix(q[len(strings.TrimSuffix(dir, "/")):], "/")
	comp, rest, _ := strings.Cut(tail, "/")
	if why := g.e.rv.refusedWhy(dir); why != "" {
		g.rec(dir, why == whyCredLink)
		return nil
	}
	var next []string
	for _, name := range g.e.matchNames(dir, comp) {
		f := path.Join(dir, name)
		if rest == "" {
			g.take(f)
			continue
		}
		if credPath(f) {
			continue
		}
		if why := g.e.rv.refusedWhy(f); why != "" {
			g.rec(f, why == whyCredLink)
			continue
		}
		if fi, err := g.e.Stat(f); err == nil && fi.Type == TypeDir {
			next = append(next, f+"/"+rest)
		}
	}
	return next
}

// take is es_glob_take: keep an existing path that is no store, no link into one and not on a
// network or autofs mount.
func (g *globber) take(p string) {
	if credPath(p) {
		return
	}
	if why := g.e.rv.refusedWhy(p); why != "" {
		g.rec(p, why == whyCredLink)
		return
	}
	if g.e.Exists(p) {
		g.out = append(g.out, p)
	}
}

// matchNames lists a vetted folder and returns the names matching one glob component (a
// leading "." must be matched explicitly, like the shell).
func (e *realEnv) matchNames(dir, comp string) []string {
	r, err := e.rv.vet(dir)
	if err != nil {
		return nil
	}
	des, err := os.ReadDir(e.rv.real(r))
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range des {
		n := d.Name()
		if strings.HasPrefix(n, ".") && !strings.HasPrefix(comp, ".") {
			continue
		}
		if ok, err := path.Match(comp, n); err == nil && ok {
			out = append(out, n)
		}
	}
	return out
}

func indexMeta(s string) int { return strings.IndexAny(s, "*?[") }

// parentOf is the folder part of a path prefix ("/" for "/x").
func parentOf(prefix string) string {
	i := strings.LastIndexByte(prefix, '/')
	if i <= 0 {
		return "/"
	}
	return prefix[:i]
}
