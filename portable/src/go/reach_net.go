// reach_net.go: net.reachability (--net; port of src/sh/28-reach.sh; owner: probes-c). The only
// file of the program that opens sockets. Only proxies and internal mirrors found in local
// configuration (facts proxy_hosts and endpoints_internal) are checked; public registries and
// net_never hosts are never looked up; every resolved address is vetted, and the TCP connection
// goes to the vetted address (re-checked in Dialer.Control), never to the name. Name lookups use
// Go's own resolver (no NSS modules, no cgo), TCP only: no HTTP, no TLS.
package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() {
	registerProbe("net.reachability", probeNetReachability)
}

const (
	lookupTimeout  = 5 * time.Second
	connectTimeout = 3 * time.Second
	hostBudget     = 10 * time.Second // a host costs up to 5 s lookup + 4 s connect
)

// reachLookup and reachConnect are the only network calls; tests replace them.
var (
	reachLookup  = goLookup
	reachConnect = goConnect
)

// goLookup asks Go's resolver for A and AAAA records apart: the resolver hands IPv4 answers back
// as IPv4-mapped IPv6 values, so the A answers are unmapped while an AAAA answer that really is
// ::ffff:a.b.c.d keeps that form (and is refused by the IPv6 rule).
func goLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	res := &net.Resolver{PreferGo: true}
	v4, err4 := res.LookupNetIP(ctx, "ip4", host)
	v6, err6 := res.LookupNetIP(ctx, "ip6", host)
	out := make([]netip.Addr, 0, len(v4)+len(v6))
	for _, a := range v4 {
		out = append(out, a.Unmap())
	}
	out = append(out, v6...)
	if len(out) > 0 {
		return out, nil
	}
	if err4 != nil && !notFound(err4) {
		return nil, err4
	}
	if err6 != nil && !notFound(err6) {
		return nil, err6
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func notFound(err error) bool {
	var dns *net.DNSError
	var ae *net.AddrError
	return errors.As(err, &dns) && dns.IsNotFound || errors.As(err, &ae)
}

// reachControl re-checks the address right before connect: nothing but a vetted address is dialled.
func reachControl(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !addrAllowed(ap.Addr()) {
		return errors.New("address refused by the scanner's network rules: " + address)
	}
	return nil
}

func goConnect(ctx context.Context, addr netip.Addr, port int) error {
	d := net.Dialer{Timeout: connectTimeout, Control: reachControl}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
	if err == nil {
		_ = c.Close()
	}
	return err
}

// reachTarget is one "host:port TAB source" line of sh es_reach_targets.
type reachTarget struct{ hp, source string }

func reachTargets(e Env) []reachTarget {
	all := []reachTarget{}
	for _, l := range lines(e.Fact("proxy_hosts")) {
		if l != "" {
			all = append(all, reachTarget{l, "proxy"})
		}
	}
	for _, l := range lines(e.Fact("endpoints_internal")) {
		if hp := hostPort(l); l != "" && hp != "" {
			all = append(all, reachTarget{hp, "package source"})
		}
	}
	out := []reachTarget{}
	seen := map[string]bool{}
	for _, t := range all {
		if k := strings.ToLower(t.hp); !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	return out
}

// reachResult is sh es_res, es_tcp, es_ms, es_err, es_why of one target.
type reachResult struct {
	resolved     []string
	tcp, ms, err string
	why          string
	lookupFailed bool
}

// reachOne is sh es_reach_one: look HOST up by its absolute name (an IP literal is not looked
// up), vet every address, connect to the first allowed one.
func reachOne(e Env, host string, port int) reachResult {
	res := reachResult{}
	if port < 1 || port > 65535 {
		return reachResult{tcp: "error", err: "port out of range"}
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else if why := nameGuard(host); why != "" {
		return reachResult{tcp: "skipped", why: why}
	} else {
		t := lookupTimeout
		if e.Timeout() > 0 && e.Timeout() < t {
			t = e.Timeout()
		}
		ctx, cancel := context.WithTimeout(context.Background(), t)
		got, err := reachLookup(ctx, absName(host))
		cancel()
		if err != nil {
			return lookupError(err)
		}
		addrs = got
	}
	byText := map[string]netip.Addr{}
	for _, a := range addrs {
		s := addrText(a)
		if _, dup := byText[s]; !dup {
			res.resolved = append(res.resolved, s)
			byText[s] = a
		}
	}
	if len(res.resolved) == 0 {
		res.tcp, res.err = "unresolved", "the name has no address"
		return res
	}
	pick, why := pickAddr(res.resolved)
	if why != "" {
		return reachResult{tcp: "skipped", why: why}
	}
	res.tcp, res.ms, res.err = tcpCheck(byText[pick], port)
	return res
}

func lookupError(err error) reachResult {
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		return reachResult{tcp: "unresolved", err: "the name has no address"}
	}
	msg := "name lookup failed: " + firstLine(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || (dns != nil && dns.IsTimeout) {
		msg = "name lookup timed out"
	}
	return reachResult{tcp: "error", err: msg, lookupFailed: true}
}

// tcpCheck connects (3 s) and classifies: ok, refused, timeout or error.
func tcpCheck(a netip.Addr, port int) (tcp, ms, errText string) {
	if !addrAllowed(a) {
		return "error", "", "address refused by the scanner's network rules"
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout+time.Second)
	err := reachConnect(ctx, a, port)
	cancel()
	if err == nil {
		return "ok", strconv.FormatInt(time.Since(start).Milliseconds(), 10), ""
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused", "", firstLine(err.Error())
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "timeout", "", firstLine(err.Error())
	}
	return "error", "", firstLine(err.Error())
}

// splitTarget: host (lower case, brackets removed) and port of "host:port"; ok=false when the
// port is not a number.
func splitTarget(hp string) (string, string, bool) {
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return "", "", false
	}
	h, p := strings.ToLower(hp[:i]), hp[i+1:]
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h, p, isNum(p)
}

func reachItem(r *Result, h, p, source string, res reachResult) *Obj {
	o := NewObj().Set("host", h).Set("port", num(p)).Set("source", source)
	if res.tcp == "skipped" {
		r.Note("skipped %s:%s: %s", h, p, res.why)
		return o.Set("tcp", "skipped").Set("reason", res.why)
	}
	return o.Set("resolved", strList(res.resolved)).Set("tcp", strOrNil(res.tcp)).Set("ms", num(res.ms)).
		Set("error", strOrNil(res.err)).Set("reason", nil)
}

func probeNetReachability(e Env, r *Result) {
	if !e.Net() {
		r.Data.Set("targets", []any{})
		r.SetStatus(StSkipped, "network checks need --net")
		return
	}
	r.Src("DNS lookup and TCP connect (3 s) to proxy and internal mirror hosts found in net.proxy and pkg.sources only; public registries and cloud metadata or link-local addresses are never looked up or contacted")
	targets := reachTargets(e)
	if len(targets) == 0 {
		r.Data.Set("targets", []any{})
		r.SetStatus(StNotFound, "no proxy or internal mirror was found in local configuration (run together with net.proxy and pkg.sources)")
		return
	}
	items, looked, over, lfail := []any{}, 0, 0, 0
	for _, t := range targets {
		h, p, ok := splitTarget(t.hp)
		if !ok {
			continue
		}
		if !plainHost(h) {
			r.Note("not checked (not a plain host name): %s", h)
			continue
		}
		res := reachResult{tcp: "skipped", why: preVet(h)}
		if res.why == "" {
			if looked >= maxReach {
				over++
				continue
			}
			if e.Deadline().Sub(e.Now()) < hostBudget {
				r.Partial("the scan budget ran out; the remaining hosts were not checked")
				break
			}
			looked++
			port, _ := strconv.Atoi(p)
			res = reachOne(e, h, port)
		}
		if res.lookupFailed {
			lfail++
		}
		items = append(items, reachItem(r, h, p, t.source, res))
	}
	r.Data.Set("targets", items)
	if over > 0 {
		r.Note("%d more endpoint(s) not checked (at most %d looked up)", over, maxReach)
	}
	if lfail > 0 {
		r.Partial("the name lookup failed for " + strconv.Itoa(lfail) + " host(s); they were not contacted")
	}
}
