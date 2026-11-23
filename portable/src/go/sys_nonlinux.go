//go:build !linux

// sys_nonlinux.go: the system calls of a non-Linux build (tests only): none are available.
package main

import (
	"errors"
	"os"
)

var (
	errNotAvail  = errors.New("not available in this build")
	errTestsOnly = errors.New("this build is for tests only: set ENVSCAN_ROOT and ENVSCAN_TEST_OS=linux")
)

func sysOSName(vars map[string]string) string { return vars["ENVSCAN_TEST_OS"] }

func sysIds() Ids                                { return Ids{UID: -1, GID: -1, EUID: -1, EGID: -1} }
func sysRlimit(string) (Rlimit, error)           { return Rlimit{}, errNotAvail }
func sysStatfs(string) (Statfs, error)           { return Statfs{}, errNotAvail }
func sysIsatty(int) bool                         { return false }
func sysUmask() (uint32, bool)                   { return 0, false }
func fileOwner(os.FileInfo) (int, int)           { return -1, -1 }
func openNoFollow(real string) (*os.File, error) { return os.Open(real) }

// fdPath: the path an open file has now (not available here: no recheck after open).
func fdPath(*os.File) (string, bool) { return "", false }

// unixModes: Windows file modes carry no Unix permission bits.
const unixModes = false

func dirWritable(string) bool   { return true }
func catchSignals() []os.Signal { return []os.Signal{os.Interrupt} }
