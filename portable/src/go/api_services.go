// api_services.go: functions one agent implements and other files call (owner: main).
//
// Each is a variable set in the implementing file's init(), so every file compiles and can be
// tested alone (a test may install a simple stand-in). Calling one that is still nil is a bug
// and panics with its name.
package main

// ---- redaction (owner: redact; port of src/sh/awk/redact.awk; cases build/testdata/redaction.json)
var (
	redactValue  func(s string) string           // op "value"
	redactNamed  func(name, value string) string // op "named"
	redactLine   func(s string) string           // op "line"
	redactText   func(s string) string           // op "text"
	redactCmd    func(s string) string           // op "cmd"
	isSecretName func(name string) bool          // op "name"
)

// ---- proxy settings in configuration lines (owner: redact; port of src/sh/awk/proxy.awk;
// cases build/testdata/proxy.json)
type SourceLine struct{ Source, Text string } // Source "git:..." / "env:..." = key=value lines; else a config file id/path

type ProxySetting struct {
	Source   string
	Kind     string // proxy | exclusion | other
	Endpoint string // host:port, "" when none
	Key      string
	Value    string
	Text     string
}

var proxySettings func(in []SourceLine) []ProxySetting

// ---- findings, Markdown and brief (owner: report; ports of src/sh/30-findings.sh, 40-render.sh,
// 45-brief.sh). doc is the finalized (redacted) report document without "findings"; results and
// facts are what the runner collected.
var (
	computeFindings func(doc *Obj, results []*Result, facts map[string]string) []any // []*Obj
	renderMarkdown  func(doc *Obj) string
	renderBrief     func(doc *Obj, facts map[string]string) string
)
