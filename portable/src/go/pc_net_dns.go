// pc_net_dns.go: net.dns and net.firewall (port of src/sh/26-net.sh, Linux; owner: probes-c).
package main

import (
	"strings"
)

func init() {
	registerProbe("net.dns", probeNetDNS)
	registerProbe("net.firewall", probeNetFirewall)
}

// resolvWords: for each line whose first field is KEY, the fields from FROM on (from 2 = all
// arguments; nameserver takes only $2).
func resolvWords(text string, all bool, keys ...string) []string {
	out := []string{}
	for _, l := range lines(text) {
		f := awkFields(l)
		if len(f) == 0 || !contains(keys, f[0]) {
			continue
		}
		if !all {
			out = append(out, field(f, 2))
			continue
		}
		out = append(out, f[1:]...)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// hostsEntries: /etc/hosts without comments, blanks collapsed, empty lines dropped (at most 200).
func hostsEntries(text string) []any {
	out := []any{}
	for _, l := range lines(text) {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		l = strings.Join(awkFields(l), " ")
		if l == "" {
			continue
		}
		if len(out) == 200 {
			break
		}
		out = append(out, l)
	}
	return out
}

func probeNetDNS(e Env, r *Result) {
	var sv, se, opt []string
	if text, ok := readSrc(e, r, "/etc/resolv.conf", "read /etc/resolv.conf"); ok {
		sv = resolvWords(text, false, "nameserver")
		se = resolvWords(text, true, "search", "domain")
		opt = resolvWords(text, true, "options")
	}
	stub := contains(sv, "127.0.0.53") || contains(sv, "127.0.0.54")
	var up []string
	if stub {
		const rf = "/run/systemd/resolve/resolv.conf"
		if text, ok := readSrc(e, r, rf, "read "+rf+" (systemd-resolved upstream servers)"); ok {
			up = resolvWords(text, false, "nameserver")
		}
	}
	order := ""
	if text, ok := readSrc(e, r, "/etc/nsswitch.conf", "read /etc/nsswitch.conf"); ok {
		order = nssLine(text, "hosts:")
	}
	hosts := []any{}
	if text, ok := readSrc(e, r, "/etc/hosts", "read /etc/hosts"); ok {
		hosts = hostsEntries(text)
	}
	r.Data.Set("servers", strList(sv)).Set("upstream_servers", strList(up)).
		Set("systemd_resolved_stub", stub).Set("search", strList(se)).Set("options", strList(opt)).
		Set("hosts_entries", hosts).Set("resolver_order", strOrNil(order))
	svText := strings.Join(sv, "\n")
	if svText == "" {
		r.Partial("no DNS servers found")
	}
	if upText := strings.Join(up, "\n"); upText != "" {
		svText = upText
	}
	r.Fact("dns_servers", svText)
	r.Fact("dns_search", strings.Join(se, "\n"))
}

// nssLine is the source list of the first "KEY" line of nsswitch.conf, fields joined by one space.
func nssLine(text, key string) string {
	for _, l := range lines(text) {
		f := awkFields(l)
		if field(f, 1) == key {
			return strings.Join(f[1:], " ")
		}
	}
	return ""
}

// ---------------------------------------------------------------- net.firewall

// ufwState reads ENABLED= of /etc/ufw/ufw.conf ("enabled"/"disabled", "" when not set).
func ufwState(text string) string {
	for _, l := range lines(text) {
		parts := strings.Split(l, "=")
		if parts[0] != "ENABLED" {
			continue
		}
		v := strings.ToLower(field(parts, 2))
		v = strings.NewReplacer("\"", "", " ", "", "\t", "").Replace(v)
		if v == "yes" {
			return "enabled"
		}
		return "disabled"
	}
	return ""
}

func probeNetFirewall(e Env, r *Result) {
	ufw := ""
	if text, ok := readSrc(e, r, "/etc/ufw/ufw.conf", "read /etc/ufw/ufw.conf"); ok {
		ufw = ufwState(text)
	}
	var fw, nft, ipt string
	c := tool(e, r, RunOpt{}, "systemctl", "is-active", "firewalld", "nftables", "iptables")
	if c.Stdout != "" && c.Exit != 127 && c.Exit != 126 {
		l := strings.Split(strings.ReplaceAll(c.Stdout, "\r", ""), "\n")
		fw, nft, ipt = field(l, 1), field(l, 2), field(l, 3)
		switch fw {
		case "active", "inactive", "failed", "unknown", "activating":
		default:
			fw, nft, ipt = "", "", ""
		}
	}
	r.Data.Set("ufw", strOrNil(ufw)).Set("firewalld", strOrNil(fw)).Set("nftables", strOrNil(nft)).
		Set("iptables", strOrNil(ipt)).Set("macos_alf", nil).Set("profiles", nil)
	r.Note("firewall rules need root; only configuration files and service states were read")
	if ufw+fw == "" {
		r.Partial("no firewall service state could be read")
	}
}
