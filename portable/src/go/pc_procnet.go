// pc_procnet.go: decoding of /proc/net/route, ipv6_route, tcp and tcp6 (sh ES_AWK_PROCNET,
// es_proc_gateways, es_proc_routes; owner: probes-c). The kernel prints each 32-bit address word
// in the host's byte order. sh reads it from the ELF header of /proc/self/exe; the Go binary
// knows its own byte order at compile time (encoding/binary.NativeEndian), which is the
// kernel's: nothing is read for it.
package main

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// hostBigEndian is sh ES_PROC_BE (a variable so tests can decode big-endian tables).
var hostBigEndian = binary.NativeEndian.Uint16([]byte{0, 1}) == 1

// net32 puts a word of 8 hex digits into network order (upper case).
func net32(x string, be bool) string {
	x = strings.ToUpper(x)
	if be {
		return x
	}
	return substr(x, 7, 2) + substr(x, 5, 2) + substr(x, 3, 2) + substr(x, 1, 2)
}

// hexByte is awk H[XX]: the decimal text of two hex digits, "" when they are not two hex digits.
func hexByte(h string) string {
	if len(h) != 2 {
		return ""
	}
	v, err := strconv.ParseUint(h, 16, 8)
	if err != nil {
		return ""
	}
	return strconv.Itoa(int(v))
}

// ip4 decodes a /proc/net word as a dotted IPv4 address.
func ip4(x string, be bool) string {
	n := net32(x, be)
	return hexByte(substr(n, 1, 2)) + "." + hexByte(substr(n, 3, 2)) + "." + hexByte(substr(n, 5, 2)) + "." +
		hexByte(substr(n, 7, 2))
}

// procGateway is one default route of /proc/net/route: gateway ("(on-link)" when none) and interface.
type procGateway struct{ Gateway, Iface string }

// procGateways is sh es_proc_gateways on the text of /proc/net/route: the default routes
// (0.0.0.0/0, and the 0.0.0.0/1 + 128.0.0.0/1 pair of full-tunnel VPNs), de-duplicated.
func procGateways(text string, be bool) []procGateway {
	out := []procGateway{}
	seen := map[procGateway]bool{}
	for i, l := range lines(text) {
		f := awkFields(l)
		if i == 0 || len(f) < 8 {
			continue
		}
		d, m := ip4(f[1], be), ip4(f[7], be)
		full := d == "0.0.0.0" && (m == "0.0.0.0" || m == "128.0.0.0")
		if !full && !(d == "128.0.0.0" && m == "128.0.0.0") {
			continue
		}
		g := procGateway{Gateway: "(on-link)", Iface: f[0]}
		if strings.ToUpper(f[2]) != "00000000" {
			g.Gateway = ip4(f[2], be)
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// maskBits counts the set bits of an 8-hex-digit mask (byte order does not matter).
func maskBits(m string) int {
	n := 0
	for i := 0; i+2 <= len(m); i += 2 {
		v, err := strconv.ParseUint(m[i:i+2], 16, 8)
		if err != nil {
			continue
		}
		for ; v > 0; v >>= 1 {
			n += int(v & 1)
		}
	}
	return n
}

// procRoutes is sh es_proc_routes: /proc/net/route decoded like ip route.
func procRoutes(text string, be bool) []string {
	out := []string{}
	for i, l := range lines(text) {
		f := awkFields(l)
		if i == 0 || len(f) < 8 || len(f[1]) != 8 || len(f[2]) != 8 || len(f[7]) != 8 {
			continue
		}
		p := maskBits(strings.ToUpper(f[7]))
		d := ip4(f[1], be)
		r := d + "/" + strconv.Itoa(p)
		if d == "0.0.0.0" && p == 0 {
			r = "default"
		}
		if strings.ToUpper(f[2]) != "00000000" {
			r += " via " + ip4(f[2], be)
		}
		r += " dev " + f[0]
		if m := awkInt(f[6]); m > 0 {
			r += " metric " + strconv.Itoa(m)
		}
		out = append(out, r)
	}
	return out
}

// procIPv6Gateways reads /proc/net/ipv6_route: the default routes (::/0) other than the reject
// route on lo, next hop as eight groups (leading zeros dropped, no :: compression).
func procIPv6Gateways(text string) []string {
	const zero = "00000000000000000000000000000000"
	out := []string{}
	for _, l := range lines(text) {
		f := awkFields(l)
		if len(f) < 10 || f[0] != zero || f[1] != "00" || f[9] == "lo" {
			continue
		}
		g := f[4]
		if g == zero {
			out = append(out, "(on-link) dev "+f[9])
			continue
		}
		groups := make([]string, 8)
		for i := 0; i < 8; i++ {
			h := strings.TrimLeft(substr(g, i*4+1, 4), "0")
			if h == "" {
				h = "0"
			}
			groups[i] = h
		}
		out = append(out, strings.Join(groups, ":")+" dev "+f[9])
	}
	return dedupLines(out)
}

// listenSock is one LISTEN socket of /proc/net/tcp or tcp6.
type listenSock struct {
	Addr string
	Port int
}

// procListen decodes the LISTEN (0A) sockets of one /proc/net/tcp or tcp6 text, de-duplicated.
func procListen(text string, be bool) []listenSock {
	out := []listenSock{}
	seen := map[listenSock]bool{}
	for i, l := range lines(text) {
		f := awkFields(l)
		if i == 0 || field(f, 4) != "0A" {
			continue
		}
		a, p, _ := strings.Cut(field(f, 2), ":")
		a, p = strings.ToUpper(a), strings.ToUpper(p)
		hi, _ := strconv.Atoi(hexByte(substr(p, 1, 2)))
		lo, _ := strconv.Atoi(hexByte(substr(p, 3, 2)))
		s := listenSock{Addr: procAddr(a, be), Port: hi*256 + lo}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// procAddr decodes an IPv4 (8 hex digits) or IPv6 (32) socket address of /proc/net/tcp*.
func procAddr(a string, be bool) string {
	if len(a) == 8 {
		return ip4(a, be)
	}
	n := net32(substr(a, 1, 8), be) + net32(substr(a, 9, 8), be) + net32(substr(a, 17, 8), be) + net32(substr(a, 25, 8), be)
	groups := make([]string, 8)
	for w := 0; w < 8; w++ {
		groups[w] = strings.ToLower(substr(n, w*4+1, 4))
	}
	ip := strings.Join(groups, ":")
	switch {
	case ip == "0000:0000:0000:0000:0000:0000:0000:0000":
		return "::"
	case ip == "0000:0000:0000:0000:0000:0000:0000:0001":
		return "::1"
	case substr(ip, 1, 30) == "0000:0000:0000:0000:0000:ffff:":
		return "::ffff:" + hexByte(substr(n, 25, 2)) + "." + hexByte(substr(n, 27, 2)) + "." +
			hexByte(substr(n, 29, 2)) + "." + hexByte(substr(n, 31, 2))
	}
	return ip
}
