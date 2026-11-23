// report_brief_net.go: the AGENT_BRIEF.md sections after "Blockers and warnings" (port of
// es_brief_write, es_brief_network, es_brief_limits and es_brief_unchecked of 45-brief.sh).
package main

import "strings"

// field is awk $n of a tab-separated line ("" when missing).
func rpField(parts []string, n int) string {
	if n-1 < len(parts) {
		return parts[n-1]
	}
	return ""
}

// locationLines is the awk of es_brief_write over the "locations" fact (fs.locations loc.tsv:
// id, path, writable, free MB, noexec, test status).
func locationLines(text string) []string {
	var w, nw, nt string
	for _, l := range strings.Split(text, "\n") {
		p := strings.Split(l, "\t")
		switch rpField(p, 3) {
		case "true":
			item := rpField(p, 1) + " " + rpField(p, 2)
			if free := rpField(p, 4); free != "-" {
				item += " (" + free + " MB free)"
			}
			item += when(rpField(p, 5) == "true", " NOEXEC")
			w = appendSep(w, "; ", item)
		case "false":
			nw = appendSep(nw, ", ", rpField(p, 1))
		}
		if s := rpField(p, 6); s == "skipped" || s == "unknown" {
			nt = appendSep(nt, ", ", rpField(p, 1))
		}
	}
	out := []string{"- Writable: " + orDefault(w, "none"), "- Not writable: " + orDefault(nw, "none")}
	if nt != "" {
		out = append(out, "- Not tested (network mount, Desktop/Documents or sync folder, or inconclusive): "+nt)
	}
	return out
}

func (c *bctx) write() {
	c.heading("Where you can write and execute")
	if loc := c.f("locations"); loc != "" {
		for _, l := range locationLines(loc) {
			c.println(l)
		}
	} else {
		c.bl("Writable", "", "not checked (fs.locations did not run)")
	}
	if v := c.f("noexec_temp"); v != "" {
		c.bl("noexec temp mounts", shJoin(v, 5))
	}
	if c.ranNotSkipped("fs.exec_test") {
		c.bl("Execution test", ifSet(c.f("exec_blocked"), "blocked in "+c.f("exec_blocked")), "scripts ran in every writable location")
	} else {
		c.bl("Execution test", "", "not run (use --deep)")
	}
	ac := ""
	if s := c.f("selinux"); s != "" {
		ac = "SELinux " + s
	}
	if a := c.f("apparmor"); a != "" {
		ac = appendSep(ac, ", ", "AppArmor "+a+ifSet(c.f("aa_profile"), " ("+c.f("aa_profile")+")"))
	}
	if fp := c.f("fapolicyd"); fp != "" {
		ac = appendSep(ac, ", ", "fapolicyd "+fp)
	}
	c.bl("Access control", ac, c.bnone("sec.app_control", "none detected"))
	c.bl("File system", "case-sensitive "+orDefault(c.f("case_sensitive"), "unknown")+", symlinks "+orDefault(c.f("symlink"), "unknown")+
		", root read-only "+orDefault(c.f("root_ro"), "unknown"))
}

func (c *bctx) network() {
	c.heading("Network, proxy and TLS")
	switch c.f("default_route") {
	case "true":
		c.bl("Default route", "yes ("+shJoin(c.f("gateways"), 3)+")")
	case "false":
		c.bl("Default route", "NONE (isolated network)")
	default:
		c.bl("Default route", "")
	}
	s1 := orDefault(shJoin(c.f("dns_servers"), 4), c.bnone("net.dns", "none"))
	search := shJoin(c.f("dns_search"), 4)
	c.bl("DNS", s1+ifSet(search, "; search "+search))
	c.bl("Proxy", shJoin(c.f("proxy_hosts"), 5), c.bnone("net.proxy", "none configured"))
	ca := orDefault(c.f("ca_custom"), c.bnone("tls.trust", "0")) + " locally added CA(s)"
	if s := c.f("ca_subjects"); s != "" {
		ca += ": " + shJoin(s, 3)
	}
	c.bl("TLS trust", ca+"; bundle "+orDefault(c.f("ca_bundle"), "none found"))
	c.bl("Crypto", "FIPS "+orDefault(c.f("fips"), "unknown")+ifSet(c.f("crypto_policy"), ", policy "+c.f("crypto_policy"))+
		ifSet(c.f("openssl_version"), ", "+c.f("openssl_version")))
	c.bl("Listening TCP ports", strings.TrimPrefix(c.f("listen_ports"), " "), "not checked")
	if c.ranNotSkipped("net.reachability") {
		c.bl("Reachability", "see net.reachability in envscan.json")
	} else {
		c.bl("Reachability", "", "not tested (use --net)")
	}
}

func (c *bctx) limits() {
	c.heading("Limits")
	u := func(k string) string { return orDefault(c.f(k), "unknown") }
	c.bl("Open files", "soft "+u("nofile_soft")+", hard "+u("nofile_hard")+"; processes soft "+u("nproc_soft"))
	if c.f("inotify_watches")+c.f("max_map_count") != "" {
		c.bl("Kernel", "inotify watches "+u("inotify_watches")+", instances "+u("inotify_instances")+"; vm.max_map_count "+
			u("max_map_count")+"; somaxconn "+u("somaxconn"))
	}
	if v := c.f("cg_version"); v != "" {
		c.bl("cgroup", "v"+v+"; memory "+u("cg_mem")+" bytes; CPU "+u("cg_cpu")+" cores; pids "+u("cg_pids")+" (max = unlimited)")
	}
	if s := c.f("eph_start"); s != "" {
		c.bl("Ephemeral ports", s+"-"+u("eph_end")+ifSet(c.f("reserved_ports"), "; reserved "+c.f("reserved_ports")))
	}
	c.bl("Disk", "home "+u("free_home_mb")+" MB free, temp "+u("free_tmp_mb")+" MB free")
}

// probeNote is sh es_bnote: notes and error of a probe joined with "; ".
func probeNote(p *Obj) string {
	t := ""
	for _, n := range listOf(p, "notes") {
		s, _ := scalarText(n)
		t = appendSep(t, "; ", s)
	}
	if e := rpFirstLine(textOf(p, "error")); e != "" {
		t = appendSep(t, "; ", "error: "+e)
	}
	return t
}

func (c *bctx) unchecked() {
	c.heading("Not checked")
	nu := 0
	for _, id := range c.probes.Keys() {
		p := objOf(c.probes, id)
		st := textOf(p, "status")
		switch st {
		case StOK, StNotFound, StNotApplicable:
			continue
		}
		note := oneline(probeNote(p))
		line := "- " + id + ": " + st + ifSet(note, " - "+note)
		if len(line) > 300 {
			line = cutBytes(line, 300) + "..."
		}
		c.println(line)
		nu++
	}
	if nu == 0 {
		c.println("- nothing: every probe completed")
	}
}
