// engine_mounts.go: the scan-start mount table and the network/autofs mount points (port of
// es_proc_mounts, es_mounts_init, es_netmnts_init, es_on_netfs, es_netmnt_under, es_mount_of).
package main

import "strings"

// parseProcMounts parses a /proc mounts file ("device mount fstype options ..."). Every \ooo
// octal escape becomes its byte (es_proc_mounts).
func parseProcMounts(text string) []Mount {
	var out []Mount
	for _, l := range lines(text) {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		out = append(out, Mount{Device: unescapeMount(f[0]), Dir: unescapeMount(f[1]), Type: unescapeMount(f[2]), Options: unescapeMount(f[3])})
	}
	return out
}

// unescapeMount: every \ooo octal escape of /proc/*/mounts (the kernel writes space, tab,
// newline, "\" and "#" that way) becomes its byte; anything else stays as written.
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) && isOctal3(s[i+1:i+4]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isOctal3: three octal digits with a value up to 0377
func isOctal3(d string) bool {
	return d[0] >= '0' && d[0] <= '3' && d[1] >= '0' && d[1] <= '7' && d[2] >= '0' && d[2] <= '7'
}

// parseMountCmd parses Linux mount(8) output: "dev on /mnt type fs (opts)".
func parseMountCmd(text string) []Mount {
	var out []Mount
	for _, l := range lines(text) {
		dev, rest, ok := strings.Cut(l, " on ")
		if !ok {
			continue
		}
		mnt, fsPart, ok := strings.Cut(rest, " type ")
		if !ok {
			continue
		}
		fsType, optPart, _ := strings.Cut(fsPart, " ")
		opts := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(optPart), "("), ")")
		out = append(out, Mount{Device: dev, Dir: mnt, Type: fsType, Options: opts})
	}
	return out
}

// netMountPoints is es_netmnts_init: the mount points of network and autofs file systems
// ("/" is never listed: a network root file system is used as it is).
func netMountPoints(ms []Mount) []string {
	var out []string
	for _, m := range ms {
		if m.Dir != "/" && isNetworkFSType(m.Type) {
			out = append(out, m.Dir)
		}
	}
	return out
}

// onNetfs is es_on_netfs: PATH (text) is a network mount point, below one, or a UNC path.
func onNetfs(p string, netmnts []string) bool {
	if isUNC(p) {
		return true
	}
	for _, m := range netmnts {
		if p == m || strings.HasPrefix(p, m+"/") {
			return true
		}
	}
	return false
}

func isUNC(p string) bool {
	return (len(p) > 2 && p[0] == '/' && p[1] == '/' && p[2] != '/') || strings.HasPrefix(p, "\\\\")
}

// netmntUnder is es_netmnt_under: a network mount point lies below DIR.
func netmntUnder(dir string, netmnts []string) bool {
	d := strings.TrimSuffix(dir, "/")
	for _, m := range netmnts {
		if strings.HasPrefix(m, d+"/") {
			return true
		}
	}
	return false
}

// mountOf is the awk of es_mount_of: the longest mount point that holds p.
func mountOf(p string, ms []Mount) (Mount, bool) {
	best, ok := Mount{}, false
	for _, m := range ms {
		if m.Dir == "/" || p == m.Dir || strings.HasPrefix(p, m.Dir+"/") {
			if !ok || len(m.Dir) > len(best.Dir) {
				best, ok = m, true
			}
		}
	}
	return best, ok
}
