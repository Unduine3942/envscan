// api_result.go: the probe result and the probe registry (owner: main).
package main

import (
	"fmt"
	"sort"
)

// Probe statuses (schema/envscan.schema.json).
const (
	StOK            = "ok"
	StPartial       = "partial"
	StNotFound      = "not_found"
	StNotApplicable = "not_applicable"
	StDenied        = "denied"
	StTimeout       = "timeout"
	StError         = "error"
	StSkipped       = "skipped"
)

// Result is one probe's outcome. A probe function fills it; the runner sets ID, timing, and
// the final status after a panic or timeout. Facts are published to later probes, the
// findings and the brief only when the probe ended ok or partial (sh: "facts of probes that
// did not run are empty").
type Result struct {
	ID        string
	Status    string
	Data      *Obj
	Raw       *Obj // label -> Text (redacted and capped by the writer)
	Sources   []string
	Notes     []string
	Error     string
	Truncated bool
	Facts     map[string]string
}

func newResult(id string) *Result {
	return &Result{ID: id, Status: StOK, Data: NewObj(), Raw: NewObj(), Facts: map[string]string{}}
}

// Src records what the probe read or ran (footprint vocabulary: "read /etc/os-release",
// "run uname -v"). Paths are the logical paths, never the ENVSCAN_ROOT-prefixed ones.
func (r *Result) Src(format string, a ...any) {
	s := format
	if len(a) > 0 {
		s = fmt.Sprintf(format, a...)
	}
	for _, have := range r.Sources {
		if have == s {
			return
		}
	}
	r.Sources = append(r.Sources, s)
}

func (r *Result) Note(format string, a ...any) {
	s := format
	if len(a) > 0 {
		s = fmt.Sprintf(format, a...)
	}
	r.Notes = append(r.Notes, s)
}

// Partial is sh es_partial: ok becomes partial; the note (if any) is added.
func (r *Result) Partial(note string) {
	if r.Status == StOK {
		r.Status = StPartial
	}
	if note != "" {
		r.Notes = append(r.Notes, note)
	}
}

// Fail sets status error with a message.
func (r *Result) Fail(msg string) {
	r.Status = StError
	r.Error = msg
}

// SetStatus sets a terminal status (not_found, not_applicable, denied, skipped) with a note.
func (r *Result) SetStatus(status, note string) {
	r.Status = status
	if note != "" {
		r.Notes = append(r.Notes, note)
	}
}

// SetRaw keeps raw command output or file text under raw.<label> (sh es_raw; empty text is dropped).
func (r *Result) SetRaw(label, text string) {
	if text != "" {
		r.Raw.Set(label, Text{Body: text, Max: rawMaxBytes})
	}
}

// Fact is sh es_fact KEY VALUE: published as ES_F_<KEY> to later probes, findings and brief.
func (r *Result) Fact(key, value string) { r.Facts[key] = value }

// rawMaxBytes caps one raw entry (sh es_f default 65536).
const rawMaxBytes = 65536

// probeFunc implements one probe. It must use only Env (never os, syscall or os/exec directly),
// may call r.Partial/SetStatus, and may panic (the runner records an error).
type probeFunc func(e Env, r *Result)

var probeFuncs = map[string]probeFunc{}

// registerProbe is called from init() of the file that implements the probe.
func registerProbe(id string, f probeFunc) {
	if _, dup := probeFuncs[id]; dup {
		panic("duplicate probe " + id)
	}
	probeFuncs[id] = f
}

// registeredProbes is the sorted list of implemented probe ids.
func registeredProbes() []string {
	ids := make([]string, 0, len(probeFuncs))
	for id := range probeFuncs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
