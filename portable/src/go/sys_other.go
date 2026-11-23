//go:build !linux && envscan_dev

// sys_other.go: the development build (Windows, -tags envscan_dev), for tests only. It refuses
// to scan unless ENVSCAN_ROOT and ENVSCAN_TEST_OS=linux are set; uname comes from the
// ENVSCAN_TEST_CMDS table when it has "uname -s" etc. (sys_nonlinux.go has the other stubs).
package main

import "strings"

func checkBuild(vars map[string]string) error {
	if vars["ENVSCAN_ROOT"] == "" || vars["ENVSCAN_TEST_OS"] != "linux" {
		return errTestsOnly
	}
	return nil
}

func sysUname(vars map[string]string) (Uname, error) {
	t := loadTestCmds(vars)
	get := func(flag string) string { return strings.TrimSpace(t["uname "+flag].Stdout) }
	if get("-s") == "" {
		return Uname{}, errNotAvail
	}
	return Uname{Sysname: get("-s"), Nodename: get("-n"), Release: get("-r"), Version: get("-v"), Machine: get("-m")}, nil
}
