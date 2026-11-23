// pc_net_iface.go: net.interfaces and net.routes (port of src/sh/26-net.sh, Linux; owner: probes-c).
package main

import (
	"strings"
)

func init() {
	registerProbe("net.interfaces", probeNetInterfaces)
	registerProbe("net.routes", probeNetRoutes)
}

// iface is one row of sh ifaces.tsv ("" stands for sh "-").
type iface struct{ Name, MTU, MAC, State, Addrs string }

func probeNetInterfaces(e Env, r *Result) {
	list, how := ifacesFromIP(e, r)
	if how == "" {
		list, how = ifacesFromIfconfig(e, r)
	}
	if how == "" {
		if text, ok := readSrc(e, r, "/proc/net/dev", "read /proc/net/dev"); ok {
			list, how = ifacesFromProcDev(text), "proc"
		}
	}
	gws := []procGateway{}
	if text, ok := readQuiet(e, "/proc/net/route"); ok {
		r.Src("read /proc/net/route (default gateways)")
		gws = procGateways(text, hostBigEndian)
	}
	arr := []any{}
	for _, it := range list {
		arr = append(arr, ifaceObj(it, gws))
	}
	r.Data.Set("interfaces", arr)
	if how == "" {
		r.Partial("no ip, ifconfig or /proc/net/dev available")
	}
	r.Note("per-interface DNS servers are not tracked on Unix; see net.dns")
}

func ifaceObj(it iface, gws []procGateway) *Obj {
	addrs := []any{}
	if it.Addrs != "" {
		for _, a := range strings.Split(it.Addrs, ",") {
			addrs = append(addrs, a)
		}
	}
	gw := []any{}
	for _, g := range gws {
		if g.Iface == it.Name {
			gw = append(gw, g.Gateway)
		}
	}
	return NewObj().Set("name", it.Name).Set("description", nil).Set("addresses", addrs).
		Set("mac", strOrNil(it.MAC)).Set("mtu", num(it.MTU)).Set("state", strOrNil(it.State)).
		Set("gateways", gw).Set("dns", []any{}).Set("dhcp", nil)
}

// ifName is the interface name of "2: eth0@if5:" fields.
func ifName(s string) string {
	s = strings.TrimSuffix(s, ":")
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return s
}

// ifacesFromIP: ip -o link (names, mtu, mac, state) and ip -o addr (addresses).
func ifacesFromIP(e Env, r *Result) ([]iface, string) {
	c := tool(e, r, RunOpt{}, "ip", "-o", "link")
	if c.Exit != 0 || c.Stdout == "" {
		return nil, ""
	}
	byName := map[string]*iface{}
	order := []string{}
	for _, l := range lines(c.Stdout) {
		f := awkFields(l)
		nm := ifName(field(f, 2))
		it := &iface{Name: nm}
		for i := 3; i <= len(f); i++ {
			switch {
			case f[i-1] == "mtu":
				it.MTU = field(f, i+1)
			case f[i-1] == "state":
				it.State = field(f, i+1)
			case strings.HasPrefix(f[i-1], "link/"):
				it.MAC = field(f, i+1)
			}
		}
		if _, dup := byName[nm]; !dup {
			order = append(order, nm)
		}
		byName[nm] = it
	}
	a, _ := needTool(e, r, RunOpt{}, "ip", "-o", "addr")
	for _, l := range lines(a.Stdout) {
		f := awkFields(l)
		if t := field(f, 3); t == "inet" || t == "inet6" {
			if it, ok := byName[ifName(field(f, 2))]; ok {
				it.Addrs = joinComma(it.Addrs, field(f, 4))
			}
		}
	}
	out := make([]iface, 0, len(order))
	for _, nm := range order {
		out = append(out, *byName[nm])
	}
	return out, "ip"
}

func joinComma(a, b string) string {
	if a == "" {
		return b
	}
	return a + "," + b
}

// ifacesFromIfconfig: ifconfig -a (net-tools and BSD-style output).
func ifacesFromIfconfig(e Env, r *Result) ([]iface, string) {
	c := tool(e, r, RunOpt{}, "ifconfig", "-a")
	if c.Exit != 0 || c.Stdout == "" {
		return nil, ""
	}
	out := []iface{}
	var cur *iface
	for _, l := range lines(c.Stdout) {
		if l != "" && l[0] != ' ' && l[0] != '\t' {
			out = append(out, iface{Name: strings.TrimSuffix(field(awkFields(l), 1), ":"), State: ifconfigState(l)})
			cur = &out[len(out)-1]
		}
		if cur != nil {
			ifconfigLine(cur, awkFields(l))
		}
	}
	return out, "ifconfig"
}

func ifconfigState(l string) string {
	for _, m := range []string{"<UP,", "<UP>", ",UP,", ",UP>", " UP ", "\tUP ", " UP\t", "\tUP\t"} {
		if strings.Contains(l, m) {
			return "UP"
		}
	}
	return "DOWN"
}

func ifconfigLine(it *iface, f []string) {
	for i := 1; i <= len(f); i++ {
		v := f[i-1]
		if v == "mtu" {
			it.MTU = field(f, i+1)
		} else if strings.HasPrefix(v, "MTU:") {
			it.MTU = strings.TrimPrefix(v, "MTU:")
		}
		if v == "ether" || v == "HWaddr" || v == "lladdr" {
			it.MAC = field(f, i+1)
		}
		if v == "inet" || v == "inet6" {
			a := field(f, i+1)
			if a == "addr:" {
				a = field(f, i+2)
			}
			if a = strings.TrimPrefix(a, "addr:"); a != "" {
				it.Addrs = joinComma(it.Addrs, a)
			}
		}
	}
}

// ifacesFromProcDev: the interface names of /proc/net/dev (nothing else is known there).
func ifacesFromProcDev(text string) []iface {
	out := []iface{}
	for i, l := range lines(text) {
		if i < 2 {
			continue
		}
		n, _, _ := strings.Cut(l, ":")
		out = append(out, iface{Name: strings.ReplaceAll(n, " ", "")})
	}
	return out
}

// ---------------------------------------------------------------- net.routes

// ipDefaults is sh es_ip_defaults: "gateway dev iface" for the default routes of ip route output,
// a full tunnel's /1 halves and the nexthop lines of a multipath default included.
func ipDefaults(text string) []string {
	out := []string{}
	mp := false
	for _, l := range lines(text) {
		f := awkFields(l)
		switch first := field(f, 1); {
		case first == "default" || first == "0.0.0.0/1" || first == "128.0.0.0/1" || first == "::/1" || first == "8000::/1":
			g := routeGw(f)
			mp = g == ""
			if g != "" {
				out = append(out, g)
			}
		case mp && first == "nexthop":
			if g := routeGw(f); g != "" {
				out = append(out, g)
			}
		default:
			mp = false
		}
	}
	return dedupLines(out)
}

func routeGw(f []string) string {
	g, d := "", ""
	for i := 1; i <= len(f); i++ {
		if f[i-1] == "via" {
			g = field(f, i+1)
			if g == "inet" || g == "inet6" {
				g = field(f, i+2)
			}
		}
		if f[i-1] == "dev" {
			d = field(f, i+1)
		}
	}
	if g == "" && d == "" {
		return ""
	}
	if g == "" {
		g = "(on-link)"
	}
	if d != "" {
		g += " dev " + d
	}
	return g
}

// nonBlankLines is awk 'NF' on command output.
func nonBlankLines(text string) []string {
	out := []string{}
	for _, l := range lines(text) {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// routeState carries sh es_gw, es_routes, es_how, es_how6 (text, joined like sh).
type routeState struct{ gw, routes, how, how6 string }

func probeNetRoutes(e Env, r *Result) {
	s := routeState{}
	if c := tool(e, r, RunOpt{}, "ip", "route"); c.Exit == 0 {
		s.how = "ip"
		s.routes = strings.Join(nonBlankLines(c.Stdout), "\n")
		s.gw = strings.Join(ipDefaults(c.Stdout), "\n")
		if c6 := tool(e, r, RunOpt{}, "ip", "-6", "route"); c6.Exit == 0 {
			s.how6 = "ip"
			if r6 := strings.Join(nonBlankLines(c6.Stdout), "\n"); r6 != "" {
				s.routes += "\n" + r6
			}
			if g6 := strings.Join(ipDefaults(c6.Stdout), "\n"); g6 != "" {
				s.gw += "\n" + g6
			}
		}
	} else if text, ok := readQuiet(e, "/proc/net/route"); ok {
		s.how = "proc"
		r.Src("read /proc/net/route")
		gl := []string{}
		for _, g := range procGateways(text, hostBigEndian) {
			gl = append(gl, g.Gateway+" dev "+g.Iface)
		}
		s.gw = strings.Join(gl, "\n")
		s.routes = strings.Join(procRoutes(text, hostBigEndian), "\n")
	}
	if s.how6 == "" {
		if text, ok := readQuiet(e, "/proc/net/ipv6_route"); ok {
			s.how6 = "proc"
			r.Src("read /proc/net/ipv6_route")
			if g6 := strings.Join(procIPv6Gateways(text), "\n"); g6 != "" {
				if s.gw != "" {
					s.gw += "\n"
				}
				s.gw += g6
			}
		}
	}
	routesData(r, s)
}

func routesData(r *Result, s routeState) {
	r.Data.Set("default_gateways", strList(lines(s.gw)))
	r.Data.Set("routes", strList(lines(s.routes)))
	fam := []any{}
	if s.how != "" {
		fam = append(fam, "ipv4")
	}
	if s.how6 != "" {
		fam = append(fam, "ipv6")
	}
	r.Data.Set("families_checked", fam)
	dr := ""
	switch {
	case s.gw != "":
		dr = "true"
	case s.how != "" && s.how6 != "":
		dr = "false"
	case s.how != "":
		r.Note("no IPv4 default route; IPv6 routes could not be checked")
	}
	r.Data.Set("default_route", boolOrNil(dr))
	if s.how == "" {
		r.Partial("no quiet routing source (ip, /proc/net/route, route get); netstat is only used with --deep")
	}
	r.Fact("default_route", dr)
	r.Fact("gateways", s.gw)
}
