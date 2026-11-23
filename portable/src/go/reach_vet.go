// reach_vet.go: the address and host rules of net.reachability (port of src/sh/28-reach.sh;
// owner: probes-c). Pure text and netip checks: nothing here touches the network.
package main

import (
	"net/netip"
	"path"
	"strconv"
	"strings"
)

const (
	maxReach  = 20
	v6Why     = "IPv6 address outside the global and unique-local ranges; never contacted"
	v4Why     = "public IPv4 address; never contacted"
	neverWhy  = "cloud metadata or link-local address; never contacted"
	rebindWhy = "resolves to a cloud metadata or link-local address; never contacted"
	publicWhy = "public registry; only internal mirrors and proxies are checked"
	// a single-label name is never looked up: the resolver's search list could turn it into any
	// name of the search domains (or of the internet, through suffix devolution)
	singleLabelWhy = "single-label name; DNS search domains could expand it, so it is not looked up"
	malformedWhy   = "malformed host name; not looked up"
)

// ip4Ok is sh es_ip4_ok: a dotted-quad IPv4 address (no leading zeros) in 10/8, 172.16/12,
// 192.168/16 or 100.64/10.
func ip4Ok(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	o := [4]int{}
	for i, p := range parts {
		if p == "" || len(p) > 3 || !allDigits(p) || (len(p) > 1 && p[0] == '0') {
			return false
		}
		v, _ := strconv.Atoi(p)
		if v > 255 {
			return false
		}
		o[i] = v
	}
	switch o[0] {
	case 10:
		return true
	case 172:
		return o[1] >= 16 && o[1] <= 31
	case 192:
		return o[1] == 168
	case 100:
		return o[1] >= 64 && o[1] <= 127
	}
	return false
}

// ip6Ok is sh es_ip6_ok: the first hextet is 2000-3fff or fc00-fdff, not fd00:ec2::/32, no zone id.
func ip6Ok(s string) bool {
	s = strings.ToLower(s)
	if s == "" || strings.Contains(s, "%") {
		return false
	}
	h, rest, _ := strings.Cut(s, ":")
	if h == "" || len(h) > 4 || strings.Trim(h, "0123456789abcdef") != "" {
		return false
	}
	v, _ := strconv.ParseUint(h, 16, 32)
	if v >= 0x2000 && v <= 0x3fff {
		return true
	}
	if v < 0xfc00 || v > 0xfdff {
		return false
	}
	if v == 0xfd00 {
		second, _, _ := strings.Cut(rest, ":")
		for len(second) > 1 && second[0] == '0' {
			second = second[1:]
		}
		if second == "ec2" {
			return false
		}
	}
	return true
}

// netNever is sh es_net_never: HOST (name or address, any case, brackets allowed) must never be
// resolved or contacted; an entry ending in "." or ":" is a prefix, others must match whole.
func netNever(host string) bool {
	h := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(host), "["), "]"), ".")
	if h == "" {
		return false
	}
	for _, n := range spec.NetNever {
		if strings.HasSuffix(n, ".") || strings.HasSuffix(n, ":") {
			if strings.HasPrefix(h, n) {
				return true
			}
		} else if h == n {
			return true
		}
	}
	return false
}

// publicHost is sh es_public_host: lower-case HOST is (under) a public registry host.
func publicHost(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(h), ".") // "pypi.org." is pypi.org
	for _, p := range spec.PublicHosts {
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// plainHost: only plain host names (letters, digits, . _ -) and IPv6 text (hex, ":", ".").
func plainHost(h string) bool {
	if strings.Contains(h, ":") {
		return strings.Trim(h, "0123456789abcdef:.") == ""
	}
	if h == "" || !(h[0] >= 'a' && h[0] <= 'z' || h[0] >= '0' && h[0] <= '9') {
		return false
	}
	return strings.Trim(h, "abcdefghijklmnopqrstuvwxyz0123456789._-") == ""
}

// looksIPv4 is the sh pattern [0-9]*.[0-9]*.[0-9]*.[0-9]* on a host.
func looksIPv4(h string) bool {
	ok, _ := path.Match("[0-9]*.[0-9]*.[0-9]*.[0-9]*", h)
	return ok
}

// preVet: why HOST is skipped before any lookup ("" = it may be looked up).
func preVet(h string) string {
	switch {
	case netNever(h):
		return neverWhy
	case publicHost(h):
		return publicWhy
	case strings.Contains(h, ":") && !ip6Ok(h):
		return v6Why
	case looksIPv4(h) && !ip4Ok(h):
		return v4Why
	}
	return nameGuard(h)
}

// nameGuard: why HOST may not be handed to a resolver ("" = it may; an address literal is never
// resolved anyway): IPv6 or IPv4 text that is no address ("fd00::1.", "10.0.0.1."), a malformed
// name, a single-label name.
func nameGuard(h string) string {
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	switch {
	case strings.Contains(h, ":"):
		return v6Why
	case looksIPv4(h):
		return v4Why
	case malformedName(h):
		return malformedWhy
	case singleLabel(h):
		return singleLabelWhy
	}
	return ""
}

// malformedName: H holds ".." anywhere (as written), or once ONE trailing "." is removed it is
// empty or starts with ".".
func malformedName(h string) bool {
	n := strings.TrimSuffix(h, ".")
	return n == "" || n[0] == '.' || strings.Contains(h, "..")
}

// singleLabel: H is a host name (not an IP literal) without any "." once ONE trailing "." is
// removed ("proxy", "proxy.", "localhost").
func singleLabel(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil || strings.Contains(h, ":") {
		return false
	}
	return !strings.Contains(strings.TrimSuffix(h, "."), ".")
}

// absName: the absolute form of a host name (one trailing "."), so the resolver applies no
// search list, ndots or suffix devolution.
func absName(h string) string { return strings.TrimSuffix(h, ".") + "." }

// addrText is the text form of a resolved address used for the rules (zone kept, so that
// ip6Ok refuses it; an IPv4-mapped IPv6 address stays "::ffff:a.b.c.d").
func addrText(a netip.Addr) string { return a.String() }

// pickAddr is the vetting of resolved addresses (sh es_reach_one): the first allowed IPv4
// address, else the first allowed IPv6 one; why is set when nothing may be contacted.
func pickAddr(addrs []string) (pick, why string) {
	a4, a6, v4 := "", "", false
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if netNever(a) {
			return "", rebindWhy
		}
		if strings.Contains(a, ":") {
			if a6 == "" && ip6Ok(a) {
				a6 = a
			}
			continue
		}
		v4 = true
		if a4 == "" && ip4Ok(a) {
			a4 = a
		}
	}
	switch {
	case a4 != "":
		return a4, ""
	case a6 != "":
		return a6, ""
	case v4:
		return "", v4Why
	}
	return "", v6Why
}

// addrAllowed re-checks an address right before a connection (Dialer.Control): allowed text
// form, no zone, not net-never, and none of the special ranges in any spelling.
func addrAllowed(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || netNever(a.String()) {
		return false
	}
	if a.Is4In6() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		return ip4Ok(a.String())
	}
	return ip6Ok(a.String())
}
