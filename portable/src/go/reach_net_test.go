package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeNet replaces the resolver and the TCP connect; it records every call.
type fakeNet struct {
	answers  map[string][]string
	failures map[string]error
	refuse   map[string]bool
	lookups  []string
	connects []string
}

func installFakeNet(t *testing.T) *fakeNet {
	f := &fakeNet{answers: map[string][]string{}, failures: map[string]error{}, refuse: map[string]bool{}}
	oldL, oldC := reachLookup, reachConnect
	reachLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		f.lookups = append(f.lookups, host)
		key := strings.TrimSuffix(host, ".") // the probe asks for the absolute name
		if err := f.failures[key]; err != nil {
			return nil, err
		}
		out := []netip.Addr{}
		for _, a := range f.answers[key] {
			out = append(out, netip.MustParseAddr(a))
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return out, nil
	}
	reachConnect = func(_ context.Context, a netip.Addr, port int) error {
		ap := netip.AddrPortFrom(a, uint16(port)).String()
		f.connects = append(f.connects, ap)
		if f.refuse[ap] {
			return &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}
		return nil
	}
	t.Cleanup(func() { reachLookup, reachConnect = oldL, oldC })
	return f
}

func reachEnv(t *testing.T, proxies ...string) *fakeEnv {
	e := newFakeEnv(t, "")
	e.NetOn = true
	e.FactsIn["proxy_hosts"] = strings.Join(proxies, "\n")
	return e
}

func reachItems(t *testing.T, r *Result) map[string]*Obj {
	out := map[string]*Obj{}
	for _, o := range objs(t, get(t, r.Data, "targets")) {
		out[o.Str("host")+":"+plainString(get(t, o, "port"))] = o
	}
	return out
}

func TestReachDefaultTierNeverTouchesTheNetwork(t *testing.T) {
	f := installFakeNet(t)
	e := reachEnv(t, "proxy.corp:3128", "10.0.0.9:3128")
	e.NetOn = false
	r := run(e, "net.reachability", probeNetReachability)
	eq(t, "status", r.Status, StSkipped)
	eq(t, "calls", len(f.lookups)+len(f.connects), 0)
}

func TestReachVetsNamesAndAddresses(t *testing.T) {
	f := installFakeNet(t)
	f.answers["proxy.corp"] = []string{"10.0.0.5"}
	f.answers["rebind.corp"] = []string{"169.254.169.254"}
	f.answers["public.corp"] = []string{"203.0.113.5"}
	f.answers["mixedv4.corp"] = []string{"203.0.113.6", "192.168.1.5"}
	f.answers["ula.corp"] = []string{"fd12:3456::7"}
	f.answers["mapped.corp"] = []string{"::ffff:10.0.0.5"}
	f.answers["ec2v6.corp"] = []string{"fd00:ec2::1"}
	f.failures["broken.corp"] = errors.New("server misbehaving")
	f.failures["slow.corp"] = context.DeadlineExceeded
	f.refuse["10.0.0.9:3128"] = true
	e := reachEnv(t, "proxy.corp:3128", "rebind.corp:80", "public.corp:80", "mixedv4.corp:443", "ula.corp:3128",
		"mapped.corp:3128", "ec2v6.corp:3128", "gone.corp:3128", "broken.corp:3128", "slow.corp:3128",
		"10.0.0.9:3128", "8.8.8.8:80", "169.254.169.254:80", "metadata.google.internal:80", "registry.npmjs.org:443",
		"[fe80::1]:80", "[fd20:ce::254]:80", "[::1]:80", "bad host:80", "nexus.corp:x", "pypi.org:443")
	e.FactsIn["endpoints_internal"] = "https://nexus.corp/repo\nhttps://PROXY.corp:3128"
	f.answers["nexus.corp"] = []string{"10.0.0.6"}
	r := run(e, "net.reachability", probeNetReachability)
	it := reachItems(t, r)
	eq(t, "proxy ok", []any{it["proxy.corp:3128"].Str("tcp"), strs(t, get(t, it["proxy.corp:3128"], "resolved"))}, []any{"ok", []string{"10.0.0.5"}})
	eq(t, "nexus from package source", []string{it["nexus.corp:443"].Str("tcp"), it["nexus.corp:443"].Str("source")}, []string{"ok", "package source"})
	eq(t, "rebind", it["rebind.corp:80"].Str("reason"), rebindWhy)
	eq(t, "public v4 resolved", it["public.corp:80"].Str("reason"), v4Why)
	eq(t, "mixed", it["mixedv4.corp:443"].Str("tcp"), "ok")
	eq(t, "mapped", it["mapped.corp:3128"].Str("reason"), v6Why)
	eq(t, "ec2v6", it["ec2v6.corp:3128"].Str("reason"), v6Why)
	eq(t, "gone", []string{it["gone.corp:3128"].Str("tcp"), it["gone.corp:3128"].Str("error")}, []string{"unresolved", "the name has no address"})
	eq(t, "broken", it["broken.corp:3128"].Str("tcp"), "error")
	eq(t, "slow", it["slow.corp:3128"].Str("error"), "name lookup timed out")
	eq(t, "refused", it["10.0.0.9:3128"].Str("tcp"), "refused")
	eq(t, "public literal", it["8.8.8.8:80"].Str("reason"), v4Why)
	for _, k := range []string{"169.254.169.254:80", "metadata.google.internal:80", "fe80::1:80", "fd20:ce::254:80"} {
		eq(t, "never "+k, it[k].Str("reason"), neverWhy)
	}
	eq(t, "loopback v6", it["::1:80"].Str("reason"), v6Why)
	eq(t, "public registry", it["registry.npmjs.org:443"].Str("reason"), publicWhy)
	eq(t, "skipped keys", it["8.8.8.8:80"].Keys(), []string{"host", "port", "source", "tcp", "reason"})
	eq(t, "checked keys", it["proxy.corp:3128"].Keys(), []string{"host", "port", "source", "resolved", "tcp", "ms", "error", "reason"})
	sort.Strings(f.connects)
	eq(t, "connects", f.connects, []string{"10.0.0.5:3128", "10.0.0.6:443", "10.0.0.9:3128", "192.168.1.5:443", "[fd12:3456::7]:3128"})
	for _, h := range f.lookups {
		if publicHost(h) || netNever(h) || strings.Contains(h, ":") || looksIPv4(h) {
			t.Errorf("looked up %s", h)
		}
	}
	eq(t, "partial", r.Status, StPartial)
	eq(t, "lfail note", hasNote(r, "the name lookup failed for 2 host(s); they were not contacted"), true)
	eq(t, "not plain", hasNote(r, "not checked (not a plain host name): bad host"), true)
	eq(t, "dedup case", len(objs(t, get(t, r.Data, "targets"))), 20)
}

func TestReachCapAndBudget(t *testing.T) {
	f := installFakeNet(t)
	hosts := []string{}
	for i := 0; i < 23; i++ {
		h := "h" + itoa(i) + ".corp"
		f.answers[h] = []string{"10.1.0." + itoa(i+1)}
		hosts = append(hosts, h+":80")
	}
	r := run(reachEnv(t, hosts...), "net.reachability", probeNetReachability)
	eq(t, "looked", len(f.lookups), maxReach)
	eq(t, "over note", hasNote(r, "3 more endpoint(s) not checked (at most 20 looked up)"), true)
	f2 := installFakeNet(t)
	e := reachEnv(t, "a.corp:80")
	e.Clock = time.Now()
	short := &deadlineEnv{fakeEnv: e, end: e.Clock.Add(5 * time.Second)}
	r2 := run(short, "net.reachability", probeNetReachability)
	eq(t, "budget", []any{r2.Status, len(f2.lookups)}, []any{StPartial, 0})
	r3 := run(reachEnv(t), "net.reachability", probeNetReachability)
	eq(t, "no targets", r3.Status, StNotFound)
}

type deadlineEnv struct {
	*fakeEnv
	end time.Time
}

func (d *deadlineEnv) Deadline() time.Time { return d.end }

func TestReachControlRefusesUnvettedAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{
		"10.0.0.5:80": true, "[2001:db8::1]:80": true, "[fd12::1]:443": true,
		"169.254.169.254:80": false, "8.8.8.8:53": false, "127.0.0.1:80": false, "[fe80::1%eth0]:80": false,
		"[::ffff:10.0.0.5]:80": false, "[fd00:ec2::254]:80": false, "[ff02::1]:80": false, "nonsense": false,
	} {
		err := reachControl("tcp", addr, nil)
		eq(t, "control "+addr, err == nil, ok)
	}
	eq(t, "tcpCheck refuses", func() string { tcp, _, _ := tcpCheck(netip.MustParseAddr("169.254.169.254"), 80); return tcp }(), "error")
	eq(t, "port range", reachOne(reachEnv(t), "10.0.0.1", 70000).err, "port out of range")
}

func TestIP6Ranges(t *testing.T) {
	cases := map[string]bool{"2001:db8::1": true, "3fff:ffff::1": true, "2000::": true, "fc00::1": true, "fdff::1": true,
		"FD12:3456::7": true, "fd00::25": true, "fd00:ec3::1": true, "1fff::1": false, "4000::1": false, "fbff::1": false,
		"fe00::1": false, "fe80::1": false, "fe90::1": false, "febf::1": false, "ff02::1": false, "::1": false, "::": false,
		"::ffff:10.0.0.5": false, "64:ff9b::a00:5": false, "0:0:0:0:0:ffff:a00:5": false,
		"0000:0000:0000:0000:0000:0000:0000:0001": false, "fd00:ec2::254": false, "fd00:0ec2:0::1": false,
		"fd00:00ec2::1": false, "2001:db8::1%eth0": false, "fd00::1%25eth0": false, "12345::1": false}
	for a, want := range cases {
		eq(t, a, ip6Ok(a), want)
	}
}

func TestIP4Rule(t *testing.T) {
	cases := map[string]bool{"10.0.0.1": true, "10.255.255.255": true, "172.16.0.1": true, "172.31.255.255": true,
		"172.15.0.1": false, "172.32.0.1": false, "192.168.0.1": true, "192.169.0.1": false, "100.64.0.1": true,
		"100.127.255.255": true, "100.63.0.1": false, "100.128.0.1": false, "8.8.8.8": false, "127.0.0.1": false,
		"0.0.0.0": false, "255.255.255.255": false, "010.0.0.1": false, "10.0.0.256": false, "10.0.0": false, "fd00::1": false}
	for a, want := range cases {
		eq(t, a, ip4Ok(a), want)
	}
}

func TestLookupErrors(t *testing.T) {
	eq(t, "timeout", lookupError(&net.DNSError{Err: "i/o timeout", IsTimeout: true}).err, "name lookup timed out")
	eq(t, "other", lookupError(errors.New("boom")).err, "name lookup failed: boom")
	eq(t, "timeout classification", func() string {
		old := reachConnect
		defer func() { reachConnect = old }()
		reachConnect = func(context.Context, netip.Addr, int) error { return context.DeadlineExceeded }
		tcp, _, _ := tcpCheck(netip.MustParseAddr("10.0.0.1"), 80)
		return tcp
	}(), "timeout")
	old := reachConnect
	reachConnect = func(context.Context, netip.Addr, int) error { return errors.New("unreachable") }
	tcp, _, _ := tcpCheck(netip.MustParseAddr("10.0.0.1"), 80)
	reachConnect = old
	eq(t, "error classification", tcp, "error")
}

// The real dialer must refuse an unvetted address in Control, before any packet is sent, and
// the real resolver answers an IP literal without asking a server.
func TestRealDialerControlAndLiteralLookup(t *testing.T) {
	err := goConnect(context.Background(), netip.MustParseAddr("169.254.169.254"), 80)
	if err == nil || !strings.Contains(err.Error(), "refused by the scanner's network rules") {
		t.Fatalf("dial to metadata address: %v", err)
	}
	got, err := goLookup(context.Background(), "10.0.0.7")
	if err != nil || len(got) != 1 || got[0].String() != "10.0.0.7" {
		t.Fatalf("literal lookup: %v %v", got, err)
	}
}

// Single-label names are never looked up (a DNS search list could expand them); other names
// are asked in their absolute form, so no search domain, ndots or suffix devolution applies.
func TestReachSingleLabelAndAbsoluteNames(t *testing.T) {
	f := installFakeNet(t)
	f.answers["proxy"] = []string{"10.0.0.1"}
	f.answers["proxy.corp"] = []string{"10.0.0.5"}
	f.answers["mirror.corp"] = []string{"10.0.0.6"}
	r := run(reachEnv(t, "proxy:3128", "proxy.:3129", "PROXY:3130", "localhost:80", "proxy.corp:3128", "mirror.corp.:80",
		"10.0.0.9:3128"), "net.reachability", probeNetReachability)
	it := reachItems(t, r)
	for _, k := range []string{"proxy:3128", "proxy.:3129", "proxy:3130", "localhost:80"} {
		o := it[k]
		if o == nil {
			t.Fatalf("no item %s", k)
		}
		eq(t, k, []string{o.Str("tcp"), o.Str("reason")}, []string{"skipped", singleLabelWhy})
	}
	eq(t, "reason text", singleLabelWhy, "single-label name; DNS search domains could expand it, so it is not looked up")
	sort.Strings(f.lookups)
	eq(t, "lookups", f.lookups, []string{"mirror.corp.", "proxy.corp."})
	eq(t, "name as written", it["mirror.corp.:80"].Str("tcp"), "ok")
	eq(t, "literal still contacted", it["10.0.0.9:3128"].Str("tcp"), "ok")
	eq(t, "note", hasNote(r, "skipped proxy:3128: "+singleLabelWhy), true)
}

func TestSingleLabelRule(t *testing.T) {
	for h, want := range map[string]bool{"proxy": true, "proxy.": true, "localhost": true, "12345": true,
		"proxy..": false, "proxy.corp": false, "proxy.corp.": false, "10.0.0.1": false, "fd12::1": false, "::1": false} {
		eq(t, h, singleLabel(h), want)
	}
	eq(t, "absolute", absName("proxy.corp"), "proxy.corp.")
	eq(t, "absolute keeps one dot", absName("proxy.corp."), "proxy.corp.")
	f := installFakeNet(t)
	eq(t, "reachOne guard", reachOne(reachEnv(t), "proxy", 80).why, singleLabelWhy)
	eq(t, "guard never asks", len(f.lookups), 0)
}

// Malformed names (after ONE trailing dot is removed: empty, a leading "." or "..") are never
// looked up; an IPv4 literal with a trailing dot is a public-address skip, never a lookup.
func TestReachMalformedNamesAndDottedLiterals(t *testing.T) {
	f := installFakeNet(t)
	f.answers["a..b.corp"] = []string{"10.0.0.1"}
	f.answers["ok.corp"] = []string{"10.0.0.2"}
	r := run(reachEnv(t, "a..b.corp:80", "x..y.:82", "x..:83", "10.0.0.1.:84", "ok.corp:85"),
		"net.reachability", probeNetReachability)
	it := reachItems(t, r)
	for _, k := range []string{"a..b.corp:80", "x..y.:82", "x..:83"} {
		o := it[k]
		if o == nil {
			t.Fatalf("no item %s", k)
		}
		eq(t, k, []string{o.Str("tcp"), o.Str("reason")}, []string{"skipped", malformedWhy})
	}
	eq(t, "reason text", malformedWhy, "malformed host name; not looked up")
	eq(t, "dotted literal", []string{it["10.0.0.1.:84"].Str("tcp"), it["10.0.0.1.:84"].Str("reason")},
		[]string{"skipped", v4Why})
	sort.Strings(f.lookups)
	eq(t, "lookups", f.lookups, []string{"ok.corp."})
	for h, want := range map[string]string{"": malformedWhy, ".": malformedWhy, "..": malformedWhy, ".a.b": malformedWhy,
		"a..b": malformedWhy, "a.b..": malformedWhy, "host..": malformedWhy, "a.b.": "", "a.b": "", "proxy": singleLabelWhy, "10.0.0.1.": v4Why} {
		eq(t, "nameGuard "+h, nameGuard(h), want)
	}
	g := installFakeNet(t)
	for _, h := range []string{"a..b", ".x.y", "10.0.0.1.", "10.0.0.1..", "fd00::1."} {
		if res := reachOne(reachEnv(t), h, 80); res.tcp != "skipped" {
			t.Errorf("reachOne(%q) = %+v, want skipped", h, res)
		}
	}
	eq(t, "reachOne guard never asks", len(g.lookups), 0)
}
