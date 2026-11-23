// redact_shared_test.go: the language-neutral cases of tests/shared_cases.py
// (build/testdata/redaction.json and names.json), every case including the pending ones.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sharedRedactionCase struct {
	Name     string            `json:"name"`
	Op       string            `json:"op"`
	Args     []string          `json:"args"`
	Exact    bool              `json:"exact"`
	Expected any               `json:"expected"`
	Gone     []string          `json:"gone"`
	Kept     []string          `json:"kept"`
	Pending  map[string]string `json:"pending"`
}

// testdataDir: ENVSCAN_TESTDATA, else ../testdata next to the staged folder (build/testdata).
func testdataDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("ENVSCAN_TESTDATA"); d != "" {
		return d
	}
	return filepath.Join("..", "testdata")
}

func loadTestdata(t *testing.T, name string, v any) {
	t.Helper()
	p := filepath.Join(testdataDir(t), name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("shared test data %s: %v (run python tests/shared_cases.py or set ENVSCAN_TESTDATA)", p, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

func applyRedactionOp(t *testing.T, op string, args []string) any {
	t.Helper()
	one := map[string]func(string) string{
		"value": redactValue, "line": redactLine, "text": redactText, "cmd": redactCmd,
	}
	switch {
	case op == "name":
		return isSecretName(args[0])
	case op == "named":
		return redactNamed(args[0], args[1])
	case strings.HasPrefix(op, "twice_"):
		f := one[strings.TrimPrefix(op, "twice_")]
		return f(f(args[0]))
	}
	f, ok := one[op]
	if !ok {
		t.Fatalf("unknown op %q", op)
	}
	return f(args[0])
}

func TestRedactSharedCases(t *testing.T) {
	var cases []sharedRedactionCase
	loadTestdata(t, "redaction.json", &cases)
	if len(cases) < 100 {
		t.Fatalf("only %d redaction cases", len(cases))
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got := applyRedactionOp(t, c.Op, c.Args)
			if c.Exact {
				if got != c.Expected {
					t.Errorf("%s %q:\n got  %#v\n want %#v", c.Op, c.Args, got, c.Expected)
				}
				return
			}
			s, _ := got.(string)
			for _, g := range c.Gone {
				if strings.Contains(s, g) {
					t.Errorf("%s %q: %q still holds %q", c.Op, c.Args, s, g)
				}
			}
			for _, k := range c.Kept {
				if !strings.Contains(s, k) {
					t.Errorf("%s %q: %q lost %q", c.Op, c.Args, s, k)
				}
			}
		})
	}
}

func TestSecretNameSharedCases(t *testing.T) {
	var cases []struct {
		Name   string `json:"name"`
		Secret bool   `json:"secret"`
	}
	loadTestdata(t, "names.json", &cases)
	for _, c := range cases {
		if got := isSecretName(c.Name); got != c.Secret {
			t.Errorf("isSecretName(%q) = %v, want %v", c.Name, got, c.Secret)
		}
	}
}
