package main

import (
	"strings"
	"testing"
)

func linuxBasic(t *testing.T) *fakeEnv { return newFakeEnv(t, fixtureRoot(t, "linux-basic")) }

func TestInterfacesFromProcNetDev(t *testing.T) {
	e := linuxBasic(t)
	r := run(e, "net.interfaces", probeNetInterfaces)
	eq(t, "status", r.Status, StOK)
	ifs := map[string]*Obj{}
	for _, o := range objs(t, get(t, r.Data, "interfaces")) {
		ifs[o.Str("name")] = o
	}
	eq(t, "names", len(ifs), 3)
	eq(t, "eth0 gateways", strs(t, get(t, ifs["eth0"], "gateways")), []string{"10.20.0.1"})
	eq(t, "tun0 gateways", strs(t, get(t, ifs["tun0"], "gateways")), []string{"(on-link)"})
	eq(t, "lo mac", get(t, ifs["lo"], "mac"), nil)
	eq(t, "keys", ifs["lo"].Keys(), []string{"name", "description", "addresses", "mac", "mtu", "state", "gateways", "dns", "dhcp"})
	eq(t, "sources", r.Sources, []string{"read /proc/net/dev", "read /proc/net/route (default gateways)"})
}

const ipLink = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
`
const ipAddr = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: eth0    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\       valid_lft forever preferred_lft forever
`

func TestInterfacesFromIP(t *testing.T) {
	e := linuxBasic(t)
	bin(e, "ip -o link", fakeCmd{Stdout: ipLink})
	e.Cmds["ip -o addr"] = fakeCmd{Stdout: ipAddr}
	r := run(e, "net.interfaces", probeNetInterfaces)
	ifs := objs(t, get(t, r.Data, "interfaces"))
	eq(t, "count", len(ifs), 2)
	eq(t, "lo addrs", strs(t, get(t, ifs[0], "addresses")), []string{"127.0.0.1/8", "::1/128"})
	eq(t, "eth0 name", ifs[1].Str("name"), "eth0")
	eq(t, "eth0 mac", ifs[1].Str("mac"), "02:42:ac:11:00:02")
	eq(t, "eth0 mtu", get(t, ifs[1], "mtu"), NumText("1500"))
	eq(t, "eth0 state", ifs[1].Str("state"), "UP")
	eq(t, "eth0 gateways", strs(t, get(t, ifs[1], "gateways")), []string{"10.20.0.1"})
}

const ifconfigOut = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.4  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 00:15:5d:01:02:03  txqueuelen 1000  (Ethernet)
lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
`

func TestInterfacesFromIfconfigAndNothing(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	bin(e, "ifconfig -a", fakeCmd{Stdout: ifconfigOut})
	r := run(e, "net.interfaces", probeNetInterfaces)
	ifs := objs(t, get(t, r.Data, "interfaces"))
	eq(t, "count", len(ifs), 2)
	eq(t, "eth0", []any{ifs[0].Str("mac"), get(t, ifs[0], "mtu"), ifs[0].Str("state")}, []any{"00:15:5d:01:02:03", NumText("1500"), "UP"})
	eq(t, "lo", []any{strs(t, get(t, ifs[1], "addresses")), get(t, ifs[1], "mtu"), ifs[1].Str("state")},
		[]any{[]string{"127.0.0.1"}, NumText("65536"), "DOWN"})
	empty := run(newFakeEnv(t, t.TempDir()), "net.interfaces", probeNetInterfaces)
	eq(t, "distroless status", empty.Status, StPartial)
	eq(t, "distroless list", len(objs(t, get(t, empty.Data, "interfaces"))), 0)
}

func TestRoutesFromProcWithFullTunnel(t *testing.T) {
	r := run(linuxBasic(t), "net.routes", probeNetRoutes)
	eq(t, "gateways", strs(t, get(t, r.Data, "default_gateways")),
		[]string{"10.20.0.1 dev eth0", "(on-link) dev tun0", "fe80:0:0:0:0:0:0:1 dev eth0"})
	eq(t, "families", strs(t, get(t, r.Data, "families_checked")), []string{"ipv4", "ipv6"})
	eq(t, "routes", strs(t, get(t, r.Data, "routes")), []string{"default via 10.20.0.1 dev eth0 metric 100",
		"10.20.0.0/16 dev eth0 metric 100", "0.0.0.0/1 dev tun0", "128.0.0.0/1 dev tun0"})
	eq(t, "default_route", get(t, r.Data, "default_route"), true)
	eq(t, "fact", r.Facts["default_route"], "true")
}

func TestRoutesFromIPWithMultipath(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	bin(e, "ip route", fakeCmd{Stdout: "default proto static metric 100\n\tnexthop via 10.0.0.1 dev eth0 weight 1\n\tnexthop via 10.0.1.1 dev eth1 weight 1\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n"})
	e.Cmds["ip -6 route"] = fakeCmd{Stdout: "default via fe80::1 dev eth0 proto ra metric 1024\n"}
	r := run(e, "net.routes", probeNetRoutes)
	eq(t, "gateways", strs(t, get(t, r.Data, "default_gateways")),
		[]string{"10.0.0.1 dev eth0", "10.0.1.1 dev eth1", "fe80::1 dev eth0"})
	eq(t, "routes", len(strs(t, get(t, r.Data, "routes"))), 5)
	e2 := newFakeEnv(t, t.TempDir())
	bin(e2, "ip route", fakeCmd{Stdout: "10.0.0.0/24 dev eth0\n"})
	e2.Cmds["ip -6 route"] = fakeCmd{Stdout: ""}
	r2 := run(e2, "net.routes", probeNetRoutes)
	eq(t, "no default", get(t, r2.Data, "default_route"), false)
	e3 := newFakeEnv(t, t.TempDir())
	bin(e3, "ip route", fakeCmd{Stdout: "10.0.0.0/24 dev eth0\n"})
	e3.Cmds["ip -6 route"] = fakeCmd{Exit: 1}
	r3 := run(e3, "net.routes", probeNetRoutes)
	eq(t, "v6 unknown", get(t, r3.Data, "default_route"), nil)
	eq(t, "v6 note", hasNote(r3, "IPv6 routes could not be checked"), true)
	r4 := run(newFakeEnv(t, t.TempDir()), "net.routes", probeNetRoutes)
	eq(t, "distroless without /proc", r4.Status, StPartial)
}

func TestProcNetBigEndian(t *testing.T) {
	eq(t, "be ip4", ip4("0A140001", true), "10.20.0.1")
	eq(t, "le ip4", ip4("0100140A", false), "10.20.0.1")
	eq(t, "be v6", procAddr("00000000000000000000000000000001", true), "::1")
	eq(t, "plain v6", procAddr("20010DB8000000000000000000000001", true), "2001:0db8:0000:0000:0000:0000:0000:0001")
	eq(t, "bad hex", ip4("ZZ000000", true), ".0.0.0")
}

func TestDNS(t *testing.T) {
	r := run(linuxBasic(t), "net.dns", probeNetDNS)
	eq(t, "servers", strs(t, get(t, r.Data, "servers")), []string{"10.20.0.53", "10.20.0.54"})
	eq(t, "search", strs(t, get(t, r.Data, "search")), []string{"corp.example", "lab.corp.example"})
	eq(t, "options", strs(t, get(t, r.Data, "options")), []string{"ndots:2", "timeout:1"})
	eq(t, "order", get(t, r.Data, "resolver_order"), "files dns")
	eq(t, "hosts", strs(t, get(t, r.Data, "hosts_entries")), []string{"127.0.0.1 localhost", "10.20.1.5 build01.corp.example build01"})
	eq(t, "stub", get(t, r.Data, "systemd_resolved_stub"), false)
	eq(t, "fact", r.Facts["dns_servers"], "10.20.0.53\n10.20.0.54")
}

func TestDNSStubAndMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0\n")
	writeFile(t, root, "/run/systemd/resolve/resolv.conf", "nameserver 10.1.1.1\n")
	r := run(newFakeEnv(t, root), "net.dns", probeNetDNS)
	eq(t, "stub", get(t, r.Data, "systemd_resolved_stub"), true)
	eq(t, "upstream", strs(t, get(t, r.Data, "upstream_servers")), []string{"10.1.1.1"})
	eq(t, "fact", r.Facts["dns_servers"], "10.1.1.1")
	r2 := run(newFakeEnv(t, t.TempDir()), "net.dns", probeNetDNS)
	eq(t, "no servers", r2.Status, StPartial)
	eq(t, "order null", get(t, r2.Data, "resolver_order"), nil)
}

func TestFirewall(t *testing.T) {
	e := linuxBasic(t)
	bin(e, "systemctl is-active firewalld nftables iptables", fakeCmd{Stdout: "inactive\nactive\nunknown\n", Exit: 3})
	r := run(e, "net.firewall", probeNetFirewall)
	eq(t, "ufw", get(t, r.Data, "ufw"), "enabled")
	eq(t, "firewalld", get(t, r.Data, "firewalld"), "inactive")
	eq(t, "nftables", get(t, r.Data, "nftables"), "active")
	eq(t, "status", r.Status, StOK)
	e2 := newFakeEnv(t, t.TempDir())
	bin(e2, "systemctl is-active firewalld nftables iptables", fakeCmd{Stdout: "System has not been booted with systemd\n", Exit: 1})
	r2 := run(e2, "net.firewall", probeNetFirewall)
	eq(t, "garbage", get(t, r2.Data, "firewalld"), nil)
	eq(t, "partial", r2.Status, StPartial)
	eq(t, "ufw disabled", ufwState("ENABLED=\"no\"\n"), "disabled")
}

func TestListeningOnlyListenState(t *testing.T) {
	r := run(linuxBasic(t), "net.listening", probeNetListening)
	got := []string{}
	for _, o := range objs(t, get(t, r.Data, "tcp")) {
		got = append(got, o.Str("address")+" "+plainString(get(t, o, "port")))
	}
	eq(t, "tcp", got, []string{"0.0.0.0 8080", "127.0.0.1 5432", "::ffff:10.20.1.5 9090", "::1 631"})
	eq(t, "fact", r.Facts["listen_ports"], " 8080 5432 9090 631")
	r2 := run(newFakeEnv(t, t.TempDir()), "net.listening", probeNetListening)
	eq(t, "no proc", r2.Status, StNotApplicable)
}

const ssOut = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*
tcp   ESTAB  0      0       10.0.0.5:22       10.0.0.9:5000
`

func TestNetstat(t *testing.T) {
	e := newFakeEnv(t, "")
	bin(e, "ss -an", fakeCmd{Stdout: ssOut})
	r := run(e, "net.netstat", probeNetNetstat)
	rows := objs(t, get(t, r.Data, "listening"))
	eq(t, "rows", len(rows), 1)
	eq(t, "local", rows[0].Str("local"), "0.0.0.0:22")
	eq(t, "raw", r.Raw.Len(), 1)
	r2 := run(newFakeEnv(t, ""), "net.netstat", probeNetNetstat)
	eq(t, "none", r2.Status, StNotFound)
}

// proxyStandIn is a small stand-in for the redact agent's proxySettings: a setting whose name
// ends in "proxy" (no_proxy excluded) is a proxy; DIRECT or a value without host gives no endpoint.
func proxyStandIn(in []SourceLine) []ProxySetting {
	out := []ProxySetting{}
	for _, l := range in {
		k, v, ok := strings.Cut(strings.TrimSpace(l.Text), "=")
		if !ok {
			f := awkFields(l.Text)
			if len(f) < 2 {
				continue
			}
			k, v = f[0], f[1]
		}
		lk := strings.ToLower(k)
		if !strings.Contains(lk, "proxy") || strings.Contains(lk, "pypi") || strings.Contains(lk, "index") {
			continue
		}
		kind := "proxy"
		if strings.HasPrefix(lk, "no_proxy") {
			kind = "exclusion"
		}
		out = append(out, ProxySetting{Source: l.Source, Kind: kind, Endpoint: hostPort(v), Key: k, Value: v, Text: l.Text})
	}
	return out
}

func withProxyStandIn(t *testing.T) {
	old := proxySettings
	proxySettings = proxyStandIn
	t.Cleanup(func() { proxySettings = old })
}

func TestProxyFromSystemFilesAndEnv(t *testing.T) {
	withProxyStandIn(t)
	e := linuxBasic(t)
	e.Vars["HTTPS_PROXY"] = "http://user:pw@proxy2.corp.example"
	e.Vars["no_proxy"] = "localhost"
	e.FactsIn[pkgProxyFact] = encodePkgProxyHandoff([]ProxySetting{
		{Source: "/home/u/.npmrc", Kind: "proxy", Endpoint: "npmproxy.corp:8080", Key: "proxy", Value: "http://npmproxy.corp:8080"},
		{Source: "git:global", Kind: "proxy", Endpoint: "", Key: "http.proxy", Value: "-"},
	}, map[string]string{"/home/u/.npmrc": "npm"})
	r := run(e, "net.proxy", probeNetProxy)
	eq(t, "configured", get(t, r.Data, "proxy_configured"), true)
	eq(t, "endpoints", strs(t, get(t, r.Data, "proxy_endpoints")), []string{"proxy2.corp.example:80",
		"proxy.corp.example:3128", "apt-cache.corp.example:3142", "npmproxy.corp:8080"})
	files := map[string]bool{}
	for _, f := range objs(t, get(t, obj(t, get(t, r.Data, "system")), "files")) {
		files[f.Str("file")] = true
		if strings.Contains(f.Str("line"), "pypi-proxy") {
			t.Errorf("index url listed as proxy: %v", f.Str("line"))
		}
	}
	eq(t, "files", files, map[string]bool{"/etc/environment": true, "/etc/apt/apt.conf.d/95proxy": true})
	env := obj(t, get(t, r.Data, "env"))
	eq(t, "env keys", env.Keys(), []string{"HTTPS_PROXY", "no_proxy"})
	eq(t, "env named", get(t, env, "HTTPS_PROXY"), Named{Name: "HTTPS_PROXY", Value: "http://user:pw@proxy2.corp.example"})
	pm := objs(t, get(t, r.Data, "package_managers"))
	eq(t, "pm tools", []string{pm[0].Str("tool"), pm[1].Str("tool")}, []string{"npm", "git"})
	eq(t, "pm value", get(t, pm[1], "value"), Named{Name: "http.proxy", Value: ""})
	eq(t, "fact", r.Facts["proxy"], "true")
	r2 := run(newFakeEnv(t, t.TempDir()), "net.proxy", probeNetProxy)
	eq(t, "no handoff without the fact", len(objs(t, get(t, r2.Data, "package_managers"))), 0)
	eq(t, "none", get(t, r2.Data, "proxy_configured"), false)
}

func TestHostPort(t *testing.T) {
	cases := map[string]string{
		"http://proxy:3128": "proxy:3128", "https://p.example": "p.example:443", "socks5://s:1": "s:1",
		"socks5h://s": "s:1080", "proxy.corp:8080": "proxy.corp:8080", "x=http://a@b.c/": "b.c:80",
		"no url here": "", "\"http://q.example:81\";": "q.example:81",
	}
	for in, want := range cases {
		eq(t, in, hostPort(in), want)
	}
}
