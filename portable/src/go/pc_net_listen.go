// pc_net_listen.go: net.listening and net.netstat (port of src/sh/26-net.sh, Linux; owner: probes-c).
package main

import (
	"regexp"
	"strconv"
	"strings"
)

func init() {
	registerProbe("net.listening", probeNetListening)
	registerProbe("net.netstat", probeNetNetstat)
}

func probeNetListening(e Env, r *Result) {
	files := []string{}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if readable(e, p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		r.SetStatus(StNotApplicable, "no quiet source of listening sockets on this system (no /proc/net/tcp); run with --deep for netstat")
		r.Data.Set("tcp", []any{})
		return
	}
	tcp := []any{}
	ports := ""
	for _, p := range files {
		text, ok := readSrc(e, r, p, "read "+p+" (LISTEN state)")
		if !ok {
			continue
		}
		for _, s := range procListen(text, hostBigEndian) {
			port := strconv.Itoa(s.Port)
			tcp = append(tcp, NewObj().Set("address", s.Addr).Set("port", num(port)).
				Set("pid", nil).Set("process", nil))
			ports += " " + port
		}
	}
	r.Data.Set("tcp", tcp)
	r.Note("process names need root or a socket-to-process sweep; pid and process are null")
	r.Fact("listen_ports", ports)
}

var localAddrRe = regexp.MustCompile(`[.:][0-9]+$`)

// listenRows: "proto TAB local" of the LISTEN lines of netstat -an / ss -an output, de-duplicated.
func listenRows(text string) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, l := range lines(text) {
		if !strings.Contains(l, "LISTEN") {
			continue
		}
		f := awkFields(l)
		local := ""
		for _, v := range f {
			if localAddrRe.MatchString(v) {
				local = v
				break
			}
		}
		if local == "" || seen[f[0]+"\t"+local] {
			continue
		}
		seen[f[0]+"\t"+local] = true
		out = append(out, NewObj().Set("proto", f[0]).Set("local", local))
	}
	return out
}

func probeNetNetstat(e Env, r *Result) {
	c := tool(e, r, RunOpt{}, "netstat", "-an")
	if c.Exit != 0 {
		c = tool(e, r, RunOpt{}, "ss", "-an")
	}
	if c.Exit != 0 {
		r.SetStatus(StNotFound, "neither netstat nor ss is available")
		return
	}
	r.SetRaw("socket_table", c.Stdout)
	r.Data.Set("listening", listenRows(c.Stdout))
}
