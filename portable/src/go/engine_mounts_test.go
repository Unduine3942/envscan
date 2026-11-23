package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcMountsFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(fixtureRoot(t, "linux-basic"), "proc", "self", "mounts"))
	if err != nil {
		t.Fatal(err)
	}
	ms := parseProcMounts(string(b))
	if len(ms) != 4 || ms[2].Dir != "/mnt/data disk" || ms[3].Dir != `/mnt/back\slash` || ms[1].Type != "proc" || ms[0].Options != "rw,relatime" {
		t.Fatalf("%+v", ms)
	}
	if m, ok := mountOf("/mnt/data disk/x", ms); !ok || m.Device != "/dev/sdb1" {
		t.Fatalf("mountOf %+v", m)
	}
	if m, _ := mountOf("/etc/hosts", ms); m.Dir != "/" {
		t.Fatalf("root %+v", m)
	}
	if got := unescapeMount(`a\011b\012c\999`); got != "a\tb\nc\\999" {
		t.Fatalf("%q", got)
	}
}

// Every \ooo escape of /proc/*/mounts decodes to its byte; anything else stays as written.
func TestUnescapeMountAllOctal(t *testing.T) {
	cases := map[string]string{
		`/mnt/a\043b`: "/mnt/a#b", `/x\040y`: "/x y", `\134`: `\`, `t\011n\012`: "t\tn\n",
		`\101\102`: "AB", `\400`: `\400`, `\08`: `\08`, `end\04`: `end\04`, `\\`: `\\`, `\377`: "\xff",
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

// FUSE mounts: a fuse.* type is a network mount unless spec local_fuse lists it.
func TestNetMountsFuse(t *testing.T) {
	ms := parseProcMounts("sshfs#u@h: /mnt/ssh fuse.sshfs rw 0 0\nlxcfs /proc/cpuinfo fuse.lxcfs rw 0 0\n" +
		"b /mnt/blob fuse.blobfuse2 rw 0 0\n/dev/sdb1 /media/usb fuseblk rw 0 0\nx /mnt/f fuse rw 0 0\n" +
		"o /var/lib/c fuse.fuse-overlayfs rw 0 0\n")
	got := strings.Join(netMountPoints(ms), " ")
	if got != "/mnt/ssh /mnt/blob /mnt/f" {
		t.Fatalf("network mounts %q", got)
	}
}

func TestNetMounts(t *testing.T) {
	ms := parseProcMounts("srv:/x / nfs rw 0 0\nsrv:/h /home/u/net nfs4 rw 0 0\n/etc/auto /auto autofs rw 0 0\n/dev/a /data ext4 rw 0 0\nshort line\n")
	nm := netMountPoints(ms)
	if len(nm) != 2 || nm[0] != "/home/u/net" || nm[1] != "/auto" {
		t.Fatalf("%v", nm)
	}
	for p, want := range map[string]bool{"/home/u/net": true, "/home/u/net/a": true, "/home/u/netx": false,
		"//srv/share": true, `\\srv\share`: true, "/data": false, "///x": false} {
		if onNetfs(p, nm) != want {
			t.Errorf("onNetfs(%q) != %v", p, want)
		}
	}
	if !netmntUnder("/home/u", nm) || !netmntUnder("/", nm) || netmntUnder("/home/u/net", nm) {
		t.Fatal("netmntUnder")
	}
}

func TestParseMountCmd(t *testing.T) {
	ms := parseMountCmd("/dev/sda1 on / type ext4 (rw,relatime)\nsrv:/e on /mnt/e type nfs (rw,vers=4)\ngarbage\n")
	if len(ms) != 2 || ms[1].Type != "nfs" || ms[1].Options != "rw,vers=4" || ms[0].Dir != "/" {
		t.Fatalf("%+v", ms)
	}
}
