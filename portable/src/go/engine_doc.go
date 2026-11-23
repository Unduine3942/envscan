// engine_doc.go: the envscan/1 document (port of es_render_json_once, es_envelope, es_counts)
// and its finalisation: every string kind is replaced by its redacted text (the event types of
// json.awk), Text values are capped like json.awk read_file.
package main

import (
	"fmt"
	"runtime"
	"strings"
)

var statusOrder = []string{StOK, StPartial, StNotFound, StNotApplicable, StDenied, StTimeout, StError, StSkipped}

// runInfo is what the run block needs besides the records.
type runInfo struct {
	Started, Finished string
	DurationMS        int64
	Cwd, Out          string
	Exit              int
	Counts            map[string]int
}

// countRecords is es_counts: per-status counts and the exit code (1 when something is
// partial, denied, timed out, failed, or the budget skipped a probe).
func countRecords(recs []*runRecord) (map[string]int, int) {
	c := map[string]int{}
	for _, s := range statusOrder {
		c[s] = 0
	}
	exit := 0
	for _, r := range recs {
		c[r.Res.Status]++
		switch r.Res.Status {
		case StPartial, StDenied, StTimeout, StError:
			exit = 1
		}
		if r.Kind == "budget" {
			exit = 1
		}
	}
	return c, exit
}

// buildDoc builds the document with the probes' value kinds still in place (finalizeValue
// redacts them). safe = without probe data and raw output (the fallback of es_render_json).
func (s *scan) buildDoc(info runInfo, safe bool) *Obj {
	doc := NewObj().Set("schema", spec.Schema)
	doc.Set("scanner", NewObj().Set("name", spec.Name).Set("version", spec.Version).Set("impl", implName).
		Set("shell_version", runtime.Version()))
	doc.Set("run", s.runBlock(info))
	doc.Set("host", s.hostBlock())
	doc.Set("findings", []any{})
	probes := NewObj()
	for _, rec := range s.records {
		probes.Set(rec.Probe.ID, envelope(rec, safe))
	}
	doc.Set("probes", probes)
	return doc
}

func (s *scan) runBlock(info runInfo) *Obj {
	tiers := []any{"default"}
	if s.opts.Deep {
		tiers = append(tiers, "deep")
	}
	if s.opts.Net {
		tiers = append(tiers, "net")
	}
	counts := NewObj()
	for _, st := range statusOrder {
		counts.Set(st, info.Counts[st])
	}
	run := NewObj().Set("started_utc", info.Started).Set("finished_utc", info.Finished).
		Set("duration_ms", info.DurationMS).Set("tiers", tiers).Set("flags", flagList(s.opts.Flags)).
		Set("cwd", info.Cwd).Set("out_dir", info.Out).Set("exit_code", info.Exit).
		Set("redaction", s.opts.Redact).Set("counts", counts)
	if s.e.root != "" {
		run.Set("test_root", s.e.root)
	}
	return run
}

// flagList is es_list over ES_FLAGS: the arguments, split at line breaks, empty ones dropped.
func flagList(flags []string) []any {
	out := []any{}
	for _, f := range flags {
		out = append(out, nonEmptyLines(f)...)
	}
	return out
}

func (s *scan) hostBlock() *Obj {
	u := s.e.uname
	name := s.e.Fact("os_name")
	if name == "" {
		name = u.Sysname
	}
	ver := s.e.Fact("os_version")
	if ver == "" {
		ver = u.Release
	}
	return NewObj().Set("os_family", s.e.osName).Set("os_name", name).Set("os_version", ver).
		Set("arch", s.e.arch).Set("hostname", s.e.host)
}

// envelope is es_envelope: one probes.<id> object.
func envelope(rec *runRecord, safe bool) *Obj {
	r := rec.Res
	o := NewObj().Set("status", r.Status).Set("tier", rec.Probe.Tier).Set("scope", rec.Probe.Scope).
		Set("title", rec.Probe.Title)
	sources := []any{}
	for _, src := range r.Sources {
		sources = append(sources, nonEmptyLines(src)...)
	}
	o.Set("sources", sources).Set("duration_ms", rec.DurMS)
	data := r.Data
	if safe || data == nil {
		data = NewObj()
	}
	o.Set("data", data)
	truncated := r.Truncated
	if !safe && r.Raw.Len() > 0 {
		raw, cut := rawBlock(r.Raw)
		o.Set("raw", raw)
		truncated = truncated || cut
	}
	o.Set("truncated", truncated)
	switch {
	case safe:
		o.Set("error", "the report was written without probe data because rendering it failed")
	case r.Error != "":
		o.Set("error", firstLineOf(r.Error))
	default:
		o.Set("error", nil)
	}
	if notes := noteList(r.Notes); len(notes) > 0 {
		o.Set("notes", notes)
	}
	return o
}

// rawBlock caps the raw entries of one probe at rawMaxBytes in total (es_envelope).
func rawBlock(raw *Obj) (*Obj, bool) {
	out, total, cut := NewObj(), 0, false
	for _, k := range raw.Keys() {
		v, _ := raw.Get(k)
		body := plainString(v)
		left := rawMaxBytes - total
		if left <= 0 {
			cut = true
			break
		}
		size := len(body)
		if size > left {
			cut, size = true, left
		}
		out.Set(k, Text{Body: body, Max: size})
		total += size
	}
	return out, cut
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return strings.TrimSuffix(l, "\r")
}

func noteList(notes []string) []any {
	out := []any{}
	for _, n := range notes {
		out = append(out, nonEmptyLines(n)...)
	}
	return out
}

// ---- finalisation (redaction)

// finalizeValue returns a copy of v with every string kind replaced by its (redacted) text.
func finalizeValue(v any, redact bool) any {
	switch t := v.(type) {
	case *Obj:
		out := NewObj()
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			out.Set(k, finalizeValue(x, redact))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = finalizeValue(x, redact)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = finalizeValue(x, redact)
		}
		return out
	case nil, bool, int, int64, uint64, float64, NumText:
		return t
	}
	return finalizeString(v, redact)
}

func finalizeString(v any, redact bool) any {
	switch t := v.(type) {
	case string:
		return redactIf(redact, redactValue, t)
	case Verbatim:
		return string(t)
	case Named:
		if !redact || t.Value == "" {
			return t.Value
		}
		return redactNamed(t.Name, t.Value)
	case Line:
		return redactIf(redact, redactLine, flatten(string(t)))
	case Cmd:
		return redactIf(redact, redactCmd, flatten(string(t)))
	case Text:
		return capText(t.Body, t.Max, redact)
	case int32, int16, int8, uint, uint32, uint16, uint8:
		return t
	}
	return redactIf(redact, redactValue, fmt.Sprint(v))
}

func redactIf(redact bool, f func(string) string, s string) string {
	if !redact || s == "" {
		return s
	}
	return f(s)
}

// flatten: line breaks of l, c and v events become blanks (es_ev / es_v).
func flatten(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

const (
	noReadText   = "[UTF-16 or binary content not read]"
	truncMark    = "[... truncated]"
	pkMarkerText = "PRIVATE KEY"
)

// capText is json.awk read_file: lines (CR removed) up to max bytes counting the line breaks
// between them, then "[... truncated]"; UTF-16 or NUL content is never emitted; the text rules
// (redactText, which also replaces a text holding a private key) run on what was kept.
func capText(body string, max int, redact bool) string {
	if max <= 0 {
		max = rawMaxBytes
	}
	if strings.IndexByte(body, 0) >= 0 || strings.HasPrefix(body, "\xff\xfe") || strings.HasPrefix(body, "\xfe\xff") {
		return noReadText
	}
	var kept []string
	total, cut, stopped := 0, "", false
	for _, l := range lines(body) {
		add := len(l)
		if len(kept) > 0 {
			add++
		}
		if total+add > max {
			cut, stopped = l, true
			break
		}
		kept = append(kept, l)
		total += add
	}
	text := strings.Join(kept, "\n")
	if redact && (strings.Contains(text, pkMarkerText) || strings.Contains(cut, pkMarkerText)) {
		return redactText(strings.TrimPrefix(text+"\n"+cut, "\n"))
	}
	if stopped {
		if len(kept) > 0 {
			text += "\n"
		}
		text += truncMark
	}
	if redact && text != "" {
		text = redactText(text)
	}
	return text
}
