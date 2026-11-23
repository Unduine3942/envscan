//go:build !linux && !envscan_dev

package main

import (
	"strings"
	"testing"
)

func TestNonLinuxReleaseBuildRefuses(t *testing.T) {
	err := checkBuild(map[string]string{"ENVSCAN_ROOT": "/x", "ENVSCAN_TEST_OS": "linux"})
	if err == nil || !strings.Contains(err.Error(), "envscan runs on Linux") {
		t.Fatal(err)
	}
	if _, ok := (&realEnv{vars: map[string]string{}}).Which("git"); ok {
		t.Fatal("Which")
	}
}
