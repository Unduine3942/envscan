// report_md.go: envscan.md, port of es_render_md (src/sh/40-render.sh) and the Markdown mode of
// src/sh/awk/json.awk (md_event, md_clean, u8clean). The document is already redacted; every
// line is made valid UTF-8 (invalid bytes -> "?", control characters -> space) like u8clean.
package main

import (
	"strings"
)

func init() {
	renderMarkdown = goRenderMarkdown
}

const (
	mdMaxValue = 300  // json.awk mdmax
	mdRawMax   = 8192 // es_render_md: r events are cut at 8192 bytes
)

var mdStatuses = []string{StOK, StPartial, StNotFound, StNotApplicable, StDenied, StTimeout, StError, StSkipped}

type mdLevel struct {
	isArray bool
	key     string
	cnt     int
	items   []string
	il      int
	pend    bool
}

// mdWriter is the md_event state machine of json.awk: nested bullet lists, short arrays of
// scalars on one line, long ones (over 160 bytes) as a list.
type mdWriter struct {
	b   *strings.Builder
	lev []mdLevel // lev[0] is the (unused) level 0 of awk; lev[depth] the open container
}

func (w *mdWriter) depth() int { return len(w.lev) - 1 }

func (w *mdWriter) println(s string) {
	w.b.WriteString(s)
	w.b.WriteByte('\n')
}

// h is an "h" event: a line as it is (u8clean).
func (w *mdWriter) h(s string) { w.println(u8clean(s)) }

func mdIndent(d int) string {
	if d <= 0 {
		return ""
	}
	return strings.Repeat("  ", d)
}

// label is md_label: "" inside an array, else "key:".
func (w *mdWriter) label(d int, key string) string {
	if d >= 1 && d <= w.depth() && w.lev[d].isArray {
		return ""
	}
	return key + ":"
}

func (w *mdWriter) line(d int, label, v string) {
	if label == "" {
		w.println(mdIndent(d) + "- " + v)
		return
	}
	w.println(mdIndent(d) + "- " + label + " " + v)
}

func (w *mdWriter) flush(d int) {
	l := &w.lev[d]
	label := w.label(d-1, l.key)
	if label == "" {
		label = "(list)"
	}
	w.println(mdIndent(d-2) + "- " + label)
	for _, it := range l.items {
		w.println(mdIndent(d-1) + "- " + it)
	}
	l.pend, l.items = false, nil
}

func (w *mdWriter) open(isArray bool, key string) {
	d := w.depth()
	if d > 0 {
		if w.lev[d].isArray && w.lev[d].pend {
			w.flush(d)
		}
		w.lev[d].cnt++
		switch {
		case !isArray && w.lev[d].isArray:
			w.println(mdIndent(d-1) + "- (" + itoa(w.lev[d].cnt) + ")")
		case !isArray:
			w.println(mdIndent(d-1) + "- " + key + ":")
		}
	}
	w.lev = append(w.lev, mdLevel{isArray: isArray, key: key, pend: isArray})
}

func (w *mdWriter) close() {
	d := w.depth()
	if d == 0 {
		return
	}
	if l := w.lev[d]; l.isArray && l.pend {
		s := strings.Join(l.items, ", ")
		if len(l.items) == 0 {
			s = "(none)"
		}
		w.line(d-2, w.label(d-1, l.key), s)
	}
	w.lev = w.lev[:d]
}

func (w *mdWriter) scalar(key, text string) {
	v := mdClean(text)
	if v == "" {
		v = `""`
	}
	d := w.depth()
	if d > 0 && w.lev[d].isArray && w.lev[d].pend {
		l := &w.lev[d]
		l.items = append(l.items, v)
		l.il += len(v) + 2
		if l.il > 160 {
			w.flush(d)
		}
		return
	}
	w.lev[d].cnt++
	w.line(d-1, w.label(d, key), v)
}

// value writes one member (an object, an array or a scalar) under key.
func (w *mdWriter) value(key string, v any) {
	switch t := v.(type) {
	case *Obj:
		w.open(false, key)
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			w.value(u8clean(k), x)
		}
		w.close()
	case []any:
		w.open(true, key)
		for _, x := range t {
			w.value("-", x)
		}
		w.close()
	default:
		s, _ := scalarText(v)
		w.scalar(key, s)
	}
}

// mdClean is json.awk md_clean: one line, "|" -> "/", u8clean, at most 300 bytes + "...".
func mdClean(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.NewReplacer("\n", " / ", "\t", " ", "|", "/").Replace(v)
	v = u8clean(v)
	if len(v) > mdMaxValue {
		v = cutBytes(v, mdMaxValue) + "..."
	}
	return v
}

// mdRawText is the r event: json.awk read_file (lines without CR, cut at max bytes counting
// the line breaks between lines, then "[... truncated]"), three backquotes become three single quotes, u8clean per line.
func mdRawText(text string, max int) string {
	if text == "" {
		return ""
	}
	var out []string
	total := 0
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		l = strings.TrimSuffix(l, "\r")
		add := len(l)
		if len(out) > 0 {
			add++
		}
		if total+add > max {
			out = append(out, "[... truncated]")
			break
		}
		out = append(out, l)
		total += add
	}
	for i, l := range out {
		out[i] = u8clean(strings.ReplaceAll(l, "```", "'''"))
	}
	return strings.Join(out, "\n")
}

func goRenderMarkdown(doc *Obj) string {
	w := &mdWriter{b: &strings.Builder{}, lev: []mdLevel{{}}}
	mdHeader(w, doc)
	mdFindings(w, listOf(doc, "findings"))
	probes := objOf(doc, "probes")
	for _, id := range probes.Keys() {
		mdProbe(w, id, objOf(probes, id))
	}
	return w.b.String()
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func joinTexts(items []any, sep string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		s, _ := scalarText(it)
		parts = append(parts, s)
	}
	return strings.Join(parts, sep)
}

func mdHeader(w *mdWriter, doc *Obj) {
	sc, run, host := objOf(doc, "scanner"), objOf(doc, "run"), objOf(doc, "host")
	counts := objOf(run, "counts")
	w.h("# envscan report: " + textOf(host, "hostname"))
	w.h("")
	w.h("- " + textOf(sc, "name") + " " + textOf(sc, "version") + " (" + textOf(sc, "impl") + ", " +
		textOf(sc, "shell_version") + "), started " + textOf(run, "started_utc") + ", finished " + textOf(run, "finished_utc"))
	w.h("- tiers: " + joinTexts(listOf(run, "tiers"), ", ") + "; redaction: " + onOff(textOf(run, "redaction") == "true") +
		"; exit code " + textOf(run, "exit_code"))
	parts := make([]string, 0, len(mdStatuses))
	for _, s := range mdStatuses {
		parts = append(parts, orDefault(textOf(counts, s), "0")+" "+s)
	}
	w.h("- probes: " + itoa(objOf(doc, "probes").Len()) + " (" + strings.Join(parts, ", ") + ")")
	if root := textOf(run, "test_root"); root != "" {
		w.h("- test root (ENVSCAN_ROOT): " + root)
	}
	w.h("")
	w.h("## Findings")
	w.h("")
}

func mdFindings(w *mdWriter, findings []any) {
	if len(findings) == 0 {
		w.h("- none")
		return
	}
	for _, x := range findings {
		f, _ := x.(*Obj)
		w.h("- **[" + textOf(f, "severity") + "] " + textOf(f, "title") + "** (" + textOf(f, "id") + "): " + textOf(f, "detail"))
		w.h("  - recommendation: " + textOf(f, "recommendation"))
		w.h("  - evidence: " + joinTexts(listOf(f, "evidence"), ", "))
	}
}

// firstLine is sh es_read1 of a one-value file.
func rpFirstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return strings.TrimSuffix(l, "\r")
}

func mdProbe(w *mdWriter, id string, p *Obj) {
	w.h("")
	w.h("## " + id + " - " + textOf(p, "title"))
	w.h("")
	w.h("- status: **" + textOf(p, "status") + "** - tier " + textOf(p, "tier") + " - scope " + textOf(p, "scope") +
		" - " + orDefault(textOf(p, "duration_ms"), "0") + " ms")
	if src := listOf(p, "sources"); len(src) > 0 {
		w.h("- sources: " + joinTexts(src, "; "))
	}
	if e := rpFirstLine(textOf(p, "error")); e != "" {
		w.h("- error: " + e)
	}
	for _, n := range listOf(p, "notes") {
		s, _ := scalarText(n)
		w.h("- note: " + s)
	}
	if data := objOf(p, "data"); data.Len() > 0 {
		w.h("")
		w.value("data", data)
	}
	raw := objOf(p, "raw")
	for _, label := range raw.Keys() {
		v, _ := raw.Get(label)
		w.h("")
		w.h("raw output `" + label + "`:")
		w.println("")
		w.println("```text")
		w.println(mdRawText(plainString(v), mdRawMax))
		w.println("```")
		w.println("")
	}
}
