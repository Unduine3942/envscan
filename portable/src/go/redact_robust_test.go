// redact_robust_test.go: hostile input. Random bytes (invalid UTF-8 included) never panic, the
// output keeps every valid UTF-8 character whole, and inputs built from repeated rule triggers
// up to the length cap stay fast (every scanner is linear).
package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var redactOps = map[string]func(string) string{
	"value": func(s string) string { return redactValue(s) },
	"line":  func(s string) string { return redactLine(s) },
	"text":  func(s string) string { return redactText(s) },
	"cmd":   func(s string) string { return redactCmd(s) },
	"named": func(s string) string { return redactNamed("JAVA_OPTS", s) },
}

// fragments that trigger rules, mixed into the random input
var redactTriggers = []string{
	"password", "=", ":", "\"", "'", "\\", "@", "://", "-p", " -u ", "-H ", "Bearer ", "Basic ",
	"authorization", "<password>", "</", "<add key=\"", "value=\"", "/t/", "ghp_", "eyJ", "Pwd=",
	"mysql ", "/RP ", "\n", "\n  ", "- ", "\"\"\"", "<redacted>", "\xc3\xa4", "\xe6\x97\xa5", "\xff",
}

func randomInput(rng *rand.Rand) string {
	var b strings.Builder
	n := rng.Intn(60)
	for i := 0; i < n; i++ {
		if rng.Intn(3) == 0 {
			b.WriteByte(byte(rng.Intn(256)))
		} else {
			b.WriteString(redactTriggers[rng.Intn(len(redactTriggers))])
		}
	}
	return b.String()
}

func TestRedactRandomBytesNoPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(20261114))
	for i := 0; i < 20000; i++ {
		in := randomInput(rng)
		for name, f := range redactOps {
			out := runNoPanic(t, name, f, in)
			if utf8.ValidString(in) && !utf8.ValidString(out) {
				t.Fatalf("%s split a UTF-8 character: %q -> %q", name, in, out)
			}
		}
		isSecretName(in)
	}
}

func runNoPanic(t *testing.T, name string, f func(string) string, in string) (out string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked on %q: %v", name, in, r)
		}
	}()
	return f(in)
}

// adversarial: one trigger repeated up to the length cap, through every op
var redactAdversarial = []string{
	"a://", "aghp_", "bearer ", "basic x", "authorization", "authorization:", "Pwd=", "Pwd=\"",
	"password=\"", "password=;", "-pass '", "-pass \"", "-pass \\\"", "<password", "<password>",
	"password=\"x\" ", "a:b@", "u:p@h;", "\\\"", "'", "x=", "key=\"a\" ", "key=\"pass\" value=\"",
	"-u ", "-u a:'", "-H ", "-H \"token: ", "mysql -p ", "schtasks /rp \"", "/t/", "@", ":", "a",
	"=", "\"", "{", "<redacted>", "token: ", "<add key=\"http://a\" ", "password ", "\"//r/:_authToken\" ",
	"a;", ";a=", "\xff", "\xe6\x97\xa5", "x://a:b@c@", "password=<redacted>a;",
}

func TestRedactAdversarialIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	start := time.Now()
	for _, unit := range redactAdversarial {
		in := strings.Repeat(unit, redactMaxLen/len(unit))
		for name, f := range redactOps {
			t0 := time.Now()
			runNoPanic(t, name, f, in)
			if d := time.Since(t0); d > 2*time.Second {
				t.Errorf("%s on %q x %d took %v", name, unit, len(in)/len(unit), d)
			}
		}
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("adversarial inputs took %v", d)
	}
	t.Logf("adversarial inputs: %v", time.Since(start))
}

func FuzzRedactValue(f *testing.F) {
	for _, s := range redactTriggers {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, op := range redactOps {
			op(s)
		}
	})
}

// redactText keeps one output line per input line (callers map lines back by index); only a
// private key collapses the whole text.
func TestRedactTextOneLinePerLine(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		in := randomInput(rng)
		if strings.Contains(in, "PRIVATE KEY") {
			continue
		}
		out := redactText(in)
		if strings.Count(out, "\n") != strings.Count(in, "\n") {
			t.Fatalf("line count changed: %q -> %q", in, out)
		}
	}
	for _, c := range redactEdgeCases {
		if c.op != "text" || strings.Contains(c.args[0], "PRIVATE KEY") {
			continue
		}
		if got := redactText(c.args[0]); strings.Count(got, "\n") != strings.Count(c.args[0], "\n") {
			t.Errorf("%s: line count changed: %q", c.name, got)
		}
	}
}
