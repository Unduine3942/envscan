// engine_cred.go: the credential-store test of the read policy (port of es_cred_path,
// es_cred_norm, es_cred_match, es_ca_path and the generated es_cred_* matchers of envscan.sh).
// Text only: nothing here touches the file system. Matching ignores ASCII case, like the
// generated sh case patterns.
package main

import "strings"

// credPath is es_cred_path: PATH (or a glob pattern) names a credential store.
func credPath(p string) bool {
	if credMatch(p) {
		return true
	}
	n := p
	if needsNorm(p) {
		n = credNorm(p)
		if credMatch(n) {
			return true
		}
	}
	if !hasTrailingDotOrSpace(n) {
		return false
	}
	return credMatch(stripComponentDots(n))
}

func needsNorm(p string) bool {
	return strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.HasSuffix(p, "/.") ||
		strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.HasSuffix(p, "/") ||
		strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.Contains(p, "\\")
}

// hasTrailingDotOrSpace: a component ends with "." or " " (sh: *[. ]/* or *[. ]).
func hasTrailingDotOrSpace(p string) bool {
	if strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
		return true
	}
	return strings.Contains(p, "./") || strings.Contains(p, " /")
}

// stripComponentDots removes trailing dots and blanks of every component that is not all dots.
func stripComponentDots(p string) string {
	parts := strings.Split(p, "/")
	for i, c := range parts {
		if strings.Trim(c, ".") != "" {
			parts[i] = strings.TrimRight(c, ". ")
		}
	}
	return strings.Join(parts, "/")
}

// credNorm is es_cred_norm on Linux: empty and "." components dropped, ".." folded (dropped at
// the root), no trailing "/".
func credNorm(p string) string {
	abs := strings.HasPrefix(p, "/")
	var out []string
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".":
		case "..":
			switch {
			case len(out) == 0 && !abs:
				out = append(out, "..")
			case len(out) > 0 && out[len(out)-1] == "..":
				out = append(out, "..")
			case len(out) > 0:
				out = out[:len(out)-1]
			}
		default:
			out = append(out, c)
		}
	}
	s := strings.Join(out, "/")
	if abs {
		return "/" + s
	}
	if s == "" {
		return "."
	}
	return s
}

// credMatch is es_cred_match: the policy tests on one spelling of the path.
func credMatch(p string) bool {
	if credFolderHit(p) || credFileHit(p) {
		return true
	}
	return credKeyExt(p) && !caPath(p)
}

func credFolderHit(p string) bool {
	lp := asciiLower("/" + p + "/")
	for _, f := range spec.Credentials["folders"] {
		if strings.Contains(lp, "/"+asciiLower(f)+"/") {
			return true
		}
	}
	return false
}

func credFileHit(p string) bool {
	lp := asciiLower("/" + p)
	for _, f := range spec.Credentials["files"] {
		if strings.HasSuffix(lp, "/"+asciiLower(f)) {
			return true
		}
	}
	for _, s := range spec.Credentials["suffixes"] {
		if strings.HasSuffix(lp, asciiLower(s)) {
			return true
		}
	}
	return false
}

func credKeyExt(p string) bool {
	lp := asciiLower(p)
	for _, e := range spec.Credentials["key_extensions"] {
		if strings.HasSuffix(lp, "."+asciiLower(e)) {
			return true
		}
	}
	return false
}

// caDirMarks are the system CA folders of es_ca_path (a .pem below one is a certificate).
var caDirMarks = []string{"/ssl/certs/", "/tls/certs/", "/ca-certificates/", "/ca-trust/", "/trust-source/", "/pki/trust/"}

// caPath is es_ca_path: a CA bundle, a file in an anchor folder or system CA folder, or a trust
// store leaf name; never a name holding key, priv or secret.
func caPath(p string) bool {
	leaf := p[strings.LastIndexByte(p, '/')+1:]
	ll := asciiLower(leaf)
	if strings.Contains(ll, "key") || strings.Contains(ll, "priv") || strings.Contains(ll, "secret") {
		return false
	}
	for _, n := range spec.TrustStoreNames {
		if ll == asciiLower(n) {
			return true
		}
	}
	sp := "/" + p
	if !strings.HasSuffix(sp, ".pem") {
		return false
	}
	for _, m := range caDirMarks {
		if strings.Contains(sp, m) {
			return true
		}
	}
	for _, b := range spec.CABundles {
		if b != "" && strings.HasSuffix(sp, b) {
			return true
		}
	}
	for _, d := range spec.CAAnchorDirs {
		if d != "" && strings.Contains(sp, d+"/") {
			return true
		}
	}
	return false
}

// asciiLower lower-cases A-Z only (the sh patterns are ASCII bracket classes).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
