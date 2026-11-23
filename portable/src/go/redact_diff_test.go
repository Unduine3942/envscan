// redact_diff_test.go: optional differential check against the reference redact.awk. A
// generator (gawk --posix, LC_ALL=C over random inputs) writes a JSON list of
// {"op", "args", "want"}; set ENVSCAN_REDACT_DIFF to that file to run it. Skipped otherwise.
package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRedactDifferentialAgainstAwk(t *testing.T) {
	path := os.Getenv("ENVSCAN_REDACT_DIFF")
	if path == "" {
		t.Skip("ENVSCAN_REDACT_DIFF not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Op   string   `json:"op"`
		Args []string `json:"args"`
		Want any      `json:"want"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, c := range cases {
		got := applyRedactionOp(t, c.Op, c.Args)
		if got != c.Want {
			bad++
			if bad <= 15 {
				t.Errorf("%s %q:\n got  %q\n want %q", c.Op, c.Args, got, c.Want)
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d differ", bad, len(cases))
	}
}
