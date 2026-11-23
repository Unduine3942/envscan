// engine_resolve.go: path vetting (port of es_resolve / es_local_path). A logical path is
// resolved component by component; a component is touched (lstat, readlink) only while the path
// so far is outside network and autofs mounts and is not a credential store, so a link is
// followed only after its target has been vetted. ENVSCAN_ROOT is added only for the syscalls.
package main

import (
	"os"
	"path/filepath"
	"strings"
)

const maxLinkDepth = 32

// Refusal reasons (user-facing).
const (
	whyNet      = "network or autofs mount"
	whyCred     = "credential store"
	whyCredLink = "link to a credential store"
	whyLoop     = "too many levels of links"
)

type resolveKind int

const (
	resOK resolveKind = iota
	resNet
	resCred
	resLoop // more than maxLinkDepth links: never used unresolved
)

// resolver resolves logical paths below root ("" = the real "/").
type resolver struct {
	root    string
	netmnts []string
}

// real is the file system path of a logical (clean, absolute) path.
func (rv *resolver) real(p string) string {
	if rv.root == "" {
		return filepath.FromSlash(p)
	}
	return filepath.Join(rv.root, filepath.FromSlash(p))
}

// resolve is es_resolve: the path with every link, ".", ".." and repeated "/" resolved.
func (rv *resolver) resolve(p string) (string, resolveKind) {
	if isUNC(p) {
		return p, resNet
	}
	if !strings.HasPrefix(p, "/") {
		return p, resOK
	}
	rest, cur, n := p, "", 0
	for {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			break
		}
		var c string
		c, rest, _ = strings.Cut(rest, "/")
		if c == "." || c == ".." {
			cur = dotStep(cur, c)
			continue
		}
		cur += "/" + c
		if onNetfs(cur, rv.netmnts) {
			return joinRest(cur, rest), resNet
		}
		if credPath(cur) {
			continue
		}
		target, isLink := rv.linkTarget(cur)
		if !isLink {
			continue
		}
		if n++; n > maxLinkDepth {
			return joinRest(cur, rest), resLoop
		}
		if isUNC(target) {
			return joinRest(target, rest), resNet
		}
		cur, rest = linkBase(cur, target), joinRest(target, rest)
	}
	out := joinRest(cur, rest)
	if cur == "" {
		out = "/" + rest
	}
	if credPath(out) {
		return out, resCred
	}
	return out, resOK
}

// dotStep applies "." (nothing) or ".." (drop the last component; the root stays).
func dotStep(cur, c string) string {
	if i := strings.LastIndexByte(cur, '/'); c == ".." && i >= 0 {
		return cur[:i]
	}
	return cur
}

// linkBase: where a link target continues (the root for an absolute one, else the link's folder).
func linkBase(cur, target string) string {
	if strings.HasPrefix(target, "/") {
		return ""
	}
	return cur[:strings.LastIndexByte(cur, '/')]
}

func joinRest(cur, rest string) string {
	if rest == "" {
		return cur
	}
	return cur + "/" + rest
}

// linkTarget reads the link at a logical path (false when it is not a link).
func (rv *resolver) linkTarget(p string) (string, bool) {
	fi, err := os.Lstat(rv.real(p))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	t, err := os.Readlink(rv.real(p))
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(t), true
}

// vet resolves p fully: the resolved logical path, or a *Refusal.
func (rv *resolver) vet(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", &Refusal{Path: p, Reason: "not an absolute path"}
	}
	if credPath(p) {
		return "", &Refusal{Path: p, Reason: whyCred}
	}
	r, kind := rv.resolve(p)
	switch kind {
	case resNet:
		return "", &Refusal{Path: p, Reason: whyNet}
	case resCred:
		return "", &Refusal{Path: p, Reason: whyCredLink}
	case resLoop:
		return "", &Refusal{Path: p, Reason: whyLoop}
	}
	return r, nil
}

// vetParent resolves the folder of p and vets the last component as text (for lstat and
// readlink, which do not follow it).
func (rv *resolver) vetParent(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", &Refusal{Path: p, Reason: "not an absolute path"}
	}
	clean := strings.TrimRight(p, "/")
	base := clean[strings.LastIndexByte(clean, '/')+1:]
	if clean == "" || base == "." || base == ".." {
		return rv.vet(p)
	}
	if credPath(p) {
		return "", &Refusal{Path: p, Reason: whyCred}
	}
	parent := clean[:strings.LastIndexByte(clean, '/')]
	if parent == "" {
		parent = "/"
	}
	rp, err := rv.vet(parent)
	if err != nil {
		return "", &Refusal{Path: p, Reason: err.(*Refusal).Reason}
	}
	full := strings.TrimSuffix(rp, "/") + "/" + base
	if onNetfs(full, rv.netmnts) {
		return "", &Refusal{Path: p, Reason: whyNet}
	}
	if credPath(full) {
		return "", &Refusal{Path: p, Reason: whyCredLink}
	}
	return full, nil
}

// refusedWhy is "" or the reason p must not be touched.
func (rv *resolver) refusedWhy(p string) string {
	if _, err := rv.vet(p); err != nil {
		if r, ok := err.(*Refusal); ok {
			return r.Reason
		}
	}
	return ""
}

// normDir is es_normdir: repeated "/" collapsed, trailing "/" removed (text only).
func normDirText(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}
