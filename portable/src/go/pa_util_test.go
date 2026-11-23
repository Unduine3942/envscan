package main

import (
	"io/fs"
	"testing"
)

// paLinkEnv adds symbolic links (logical path -> target) to a fakeEnv without real links.
type paLinkEnv struct {
	*fakeEnv
	links map[string]string
}

func (l *paLinkEnv) Lstat(p string) (FileInfo, error) {
	if _, ok := l.links[p]; ok {
		return FileInfo{Name: paBase(p), Type: TypeLink}, nil
	}
	return l.fakeEnv.Lstat(p)
}

func (l *paLinkEnv) Readlink(p string) (string, error) {
	if t, ok := l.links[p]; ok {
		return t, nil
	}
	return "", fs.ErrInvalid
}

func (l *paLinkEnv) Stat(p string) (FileInfo, error) {
	rp, ok := paResolve(l, p)
	if !ok {
		return FileInfo{}, &Refusal{Path: p, Reason: "network or autofs mount"}
	}
	return l.fakeEnv.Stat(rp)
}

func TestResolveFollowsLinks(t *testing.T) {
	root := paTree(t, map[string]string{"usr/share/zoneinfo/Asia/Seoul": "TZif", "usr/bin/dash": "", "bin/": ""})
	e := &paLinkEnv{fakeEnv: newFakeEnv(t, root), links: map[string]string{
		"/etc/localtime": "../usr/share/zoneinfo/Asia/Seoul", "/bin/sh": "dash", "/bin/dash": "/usr/bin/dash",
		"/loop": "/loop", "/opt/tool": "/net/share/tool"}}
	e.NetPaths = []string{"/net"}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/etc/localtime", "/usr/share/zoneinfo/Asia/Seoul", true},
		{"/bin/sh", "/usr/bin/dash", true},
		{"/a/./b/../c", "/a/c", true},
		{"/opt/tool/x", "/net/share/tool/x", false},
		{"rel/x", "rel/x", true},
		{"/", "/", true},
	}
	for _, c := range cases {
		if got, ok := paResolve(e, c.in); got != c.want || ok != c.ok {
			t.Errorf("resolve %s = %s %v", c.in, got, ok)
		}
	}
	paResolve(e, "/loop/x") // a link loop ends after 32 links
	r := paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"timezone": "Asia/Seoul"})
	r = paRun(t, e, "shell.info")
	paWant(t, r, map[string]any{"sh_target": "dash"})
	e.links["/usr/bin/awk"] = "/bin/busybox"
	if got := paFlavor(e, "", "/usr/bin/awk"); got != "busybox" {
		t.Errorf("flavor %s", got)
	}
}

func TestWritableFromMode(t *testing.T) {
	e := newFakeEnv(t, "")
	e.MountTab = []Mount{{"/dev/sda1", "/", "ext4", "rw"}, {"/dev/sr0", "/media/cd", "iso9660", "ro,nosuid"}}
	e.IdsV = Ids{UID: 1000, EUID: 1000, GID: 100, EGID: 100, Groups: []int{100, 27}}
	cases := []struct {
		p    string
		fi   FileInfo
		want bool
	}{
		{"/home/bob", FileInfo{UID: 1000, GID: 100, Mode: 0o755}, true},
		{"/home/bob", FileInfo{UID: 1000, GID: 100, Mode: 0o555}, false},
		{"/srv/g", FileInfo{UID: 0, GID: 27, Mode: 0o775}, true},
		{"/srv/g", FileInfo{UID: 0, GID: 100, Mode: 0o755}, false},
		{"/tmp", FileInfo{UID: 0, GID: 0, Mode: 0o1777}, true},
		{"/usr", FileInfo{UID: 0, GID: 0, Mode: 0o755}, false},
		{"/media/cd", FileInfo{UID: 1000, GID: 100, Mode: 0o755}, false},
		{"/x", FileInfo{UID: -1, GID: -1, Mode: 0o644}, true},
	}
	for _, c := range cases {
		if got := paWritable(e, c.p, c.fi); got != c.want {
			t.Errorf("%s %+v = %v", c.p, c.fi, got)
		}
	}
	e.IdsV = Ids{}
	if !paWritable(e, "/usr", FileInfo{UID: 0, Mode: 0o555}) || paWritable(e, "/media/cd", FileInfo{Mode: 0o777}) {
		t.Error("root")
	}
}

func TestSmallHelpers(t *testing.T) {
	if paArch32("arm64") != "arm" || paArch32("ppc64") != "ppc" || paArch32("sparc64") != "sparc" || paArch32("s390x") != "s390x" {
		t.Error("arch32")
	}
	e := newFakeEnv(t, "")
	if w, v := paWSL(e, "4.4.0-19041-Microsoft", ""); w != "true" || v != "1" {
		t.Error("wsl1")
	}
	e.OSName = "darwin"
	if w, _ := paWSL(e, "microsoft", ""); w != "false" {
		t.Error("wsl darwin")
	}
	d := NewObj()
	paSetWSL(e, d, "false", "")
	if v, ok := d.Get("wsl"); !ok || v != nil {
		t.Error("wsl null off linux")
	}
	if !paUTCName("Etc/UTC") || !paUTCName("posix/GMT") || paUTCName("Asia/Seoul") {
		t.Error("utc names")
	}
	if !isNetworkFSType("nfs3") || !isNetworkFSType("cifs") || isNetworkFSType("ext4") || isNetworkFSType("") {
		t.Error("netfs")
	}
	if paKB("unlimited") != "unlimited" || paKB("2048") != "2" || paKB("99999999999999999999999") != "99999999999999999999999" {
		t.Error("kb")
	}
	if got := paListLines("a\n\nb\nc\n", 2, paLine); len(got) != 2 || got[1] != Line("b") {
		t.Errorf("list %v", got)
	}
	if paNumLess("5", "5") || !paNumLess("007", "8") {
		t.Error("numless")
	}
	if l := paParseProcLimits("Limit\nMax open files            1024                 4096                 files\nshort\n"); l.ns != "1024" || l.nh != "4096" {
		t.Errorf("proc limits %+v", l)
	}
}
