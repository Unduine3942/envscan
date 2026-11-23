package main

import "testing"

func TestNormArch(t *testing.T) {
	cases := map[string]string{"x86_64": "x86_64", "amd64": "x86_64", "i686": "x86", "aarch64": "arm64",
		"armv7l": "arm", "ppc64le": "ppc64le", "s390x": "s390x", "riscv64": "riscv64", "mips64": "mips",
		"sun4v": "sparc64", "weird": "other", "": "other"}
	for in, want := range cases {
		if got := normArch(in); got != want {
			t.Errorf("normArch(%q)=%q", in, got)
		}
	}
	if normArch(goArchMachine()) == "" {
		t.Fatal("go arch")
	}
}

func TestParseUmaskAndLimits(t *testing.T) {
	if u, ok := parseUmask("Name:\tx\nUmask:\t0022\nState:\tR\n"); !ok || u != 0o22 {
		t.Fatalf("%o %v", u, ok)
	}
	if _, ok := parseUmask("Name: x\n"); ok {
		t.Fatal("no umask line")
	}
	lim := "Limit                     Soft Limit           Hard Limit           Units\n" +
		"Max stack size            8388608              unlimited            bytes\n" +
		"Max open files            1024                 1048576              files\n"
	if v, ok := parseLimitsSoft(lim, "Max open files"); !ok || v != 1024 {
		t.Fatalf("%d %v", v, ok)
	}
	if v, ok := parseLimitsSoft("Max open files  unlimited unlimited files\n", "Max open files"); !ok || v != ^uint64(0) {
		t.Fatal("unlimited")
	}
	if _, ok := parseLimitsSoft(lim, "Max nothing"); ok {
		t.Fatal("missing row")
	}
	if rlimitText(^uint64(0)) != "unlimited" || rlimitText(42) != "42" {
		t.Fatal("rlimitText")
	}
}
