//go:build !linux && !envscan_dev

// sys_nodev.go: a non-Linux build without the envscan_dev tag: envscan runs on Linux only, so
// it never scans (exit 2).
package main

import "errors"

func checkBuild(map[string]string) error {
	return errors.New("envscan runs on Linux; this build is for tests only")
}

func sysUname(map[string]string) (Uname, error) { return Uname{}, errNotAvail }
