// engine_scan.go: one scan from start to exit code (port of es_main, es_init, es_render,
// es_render_json, es_render_log, es_cleanup, es_on_signal). stdout gets exactly the output
// folder path; progress and errors go to stderr.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const utcLayout = "2006-01-02T15:04:05Z"

type scan struct {
	e       *realEnv
	opts    *options
	records []*runRecord
	out     string
	stderr  io.Writer
	started string
	newRun  func(*realEnv, io.Writer) *runner
}

// runMain is the whole program: 0 ok, 1 something partial or failed, 2 fatal or usage error.
func runMain(args []string, stdout, stderr io.Writer, environ []string) int {
	vars, _ := snapshotEnv(environ)
	if err := checkBuild(vars); err != nil {
		fmt.Fprintf(stderr, "envscan: %s\n", err)
		return 2
	}
	o, err := parseArgs(args)
	if err == nil {
		switch o.Action {
		case actVersion:
			fmt.Fprintln(stdout, versionLine())
			return 0
		case actHelp:
			fmt.Fprint(stdout, usageText)
			return 0
		case actList:
			listProbes(stdout)
			return 0
		}
		err = o.checkSelections(specProbeIDs())
	}
	if err != nil {
		fmt.Fprintf(stderr, "envscan: %s\n%s", err, usageText)
		return 2
	}
	s := &scan{opts: o, stderr: stderr, newRun: newRunner}
	return s.run(stdout, environ, time.Now)
}

// run is es_init .. es_cleanup.
func (s *scan) run(stdout io.Writer, environ []string, clock func() time.Time) int {
	s.e = newRealEnv(s.opts, environ, clock)
	s.started = s.e.t0.UTC().Format(utcLayout)
	if why := s.e.rootWhy; why != "" {
		return s.fatal(fatalf("ENVSCAN_ROOT is not used (%s): %s", why, s.e.root))
	}
	stop := s.e.watchSignals(s.stderr) // before the first folder is made
	defer stop()
	defer s.e.cleanup()
	if err := s.e.initTemp(); err != nil {
		return s.fatal(err)
	}
	out, err := s.e.pickOut()
	if err != nil {
		return s.fatal(err)
	}
	s.out = out
	s.records = s.newRun(s.e, s.stderr).runAll(out)
	exit, err := s.render()
	if err != nil {
		return s.fatal(err)
	}
	s.e.cleanup()
	fmt.Fprintln(stdout, out)
	return exit
}

func (s *scan) fatal(err error) int {
	fmt.Fprintf(s.stderr, "envscan: %s\n", err)
	return 2
}

func (s *scan) say(msg string) {
	fmt.Fprintln(s.stderr, msg)
	s.e.Log(msg)
}

// watchSignals is es_on_signal: on SIGINT/SIGTERM (and HUP/QUIT on Linux) the children are
// killed, the temp and test folders removed, and the scan ends with exit 2.
func (e *realEnv) watchSignals(stderr io.Writer) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, catchSignals()...)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			fmt.Fprintln(stderr, "envscan: interrupted")
			e.cleanup()
			os.Exit(2)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// render is es_render: envscan.json, envscan.md, AGENT_BRIEF.md and envscan.log.
func (s *scan) render() (int, error) {
	counts, exit := countRecords(s.records)
	t1 := s.e.clock()
	info := runInfo{Started: s.started, Finished: t1.UTC().Format(utcLayout), Cwd: s.e.cwd, Out: s.out,
		DurationMS: max(t1.Sub(s.e.t0).Milliseconds(), 0), Exit: exit, Counts: counts}
	facts := s.e.allFacts()
	doc, err := s.finalDoc(info, facts)
	if err != nil {
		return 2, err
	}
	if err := s.writeOut("envscan.json", writeJSON(doc)); err != nil {
		return 2, err
	}
	md := s.safeText("envscan.md", func() string { return renderMarkdown(doc) })
	brief := s.safeText("AGENT_BRIEF.md", func() string { return s.redactLines(renderBrief(doc, facts), redactLine) })
	s.writeOrSay("envscan.md", md)
	s.writeOrSay("AGENT_BRIEF.md", brief)
	good := counts[StOK] + counts[StNotFound] + counts[StNotApplicable]
	s.say(fmt.Sprintf("envscan: %d probes, %d ok, %d not fully checked, %d skipped; exit %d", len(s.records),
		counts[StOK], len(s.records)-good-counts[StSkipped], counts[StSkipped], exit))
	s.writeOrSay("envscan.log", s.logFile(info))
	return exit, nil
}

// finalDoc builds and finalizes the document; when that fails it is built again without probe
// data and raw output (es_render_json).
func (s *scan) finalDoc(info runInfo, facts map[string]string) (*Obj, error) {
	doc, err := s.tryDoc(info, facts, false)
	if err == nil {
		return doc, nil
	}
	s.say("envscan: rendering envscan.json failed; writing it again without probe data")
	s.e.Log("render error: " + err.Error())
	return s.tryDoc(info, facts, true)
}

func (s *scan) tryDoc(info runInfo, facts map[string]string, safe bool) (doc *Obj, err error) {
	defer func() {
		if v := recover(); v != nil {
			doc, err = nil, fmt.Errorf("%v", v)
		}
	}()
	doc = finalizeValue(s.buildDoc(info, safe), s.opts.Redact).(*Obj)
	doc.Set("findings", s.findings(doc, facts))
	return doc, nil
}

// findings runs the findings port; a failure leaves the list empty (logged).
func (s *scan) findings(doc *Obj, facts map[string]string) (out any) {
	defer func() {
		if v := recover(); v != nil {
			s.say(fmt.Sprintf("envscan: computing the findings failed: %v", v))
			out = []any{}
		}
	}()
	results := make([]*Result, 0, len(s.records))
	for _, r := range s.records {
		results = append(results, r.Res)
	}
	f := computeFindings(doc, results, facts)
	if f == nil {
		f = []any{}
	}
	return finalizeValue(f, s.opts.Redact)
}

// safeText runs a renderer; a failure is reported and gives an empty file.
func (s *scan) safeText(name string, f func() string) (text string) {
	defer func() {
		if v := recover(); v != nil {
			s.say(fmt.Sprintf("envscan: error writing %s: %v", name, v))
			text = ""
		}
	}()
	return f()
}

// redactLines applies a line rule to every line when redaction is on (json.awk text/log mode).
func (s *scan) redactLines(text string, rule func(string) string) string {
	if text == "" {
		return ""
	}
	ls := lines(text)
	var b strings.Builder
	for _, l := range ls {
		if s.opts.Redact {
			l = redactIf(true, rule, l)
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}

// logFile is es_render_log (command-line rules on every line).
func (s *scan) logFile(info runInfo) string {
	all := []string{fmt.Sprintf("%s %s (%s) on %s, started %s, finished %s", spec.Name, spec.Version, implName,
		s.e.host, info.Started, info.Finished)}
	all = append(all, s.e.logText()...)
	all = append(all, fmt.Sprintf("exit code %d", info.Exit))
	return s.redactLines(strings.Join(all, "\n"), redactCmd)
}

func (s *scan) writeOrSay(name, text string) {
	if err := s.writeOut(name, text); err != nil {
		s.say(fmt.Sprintf("envscan: error writing %s", name))
	}
}

// writeOut creates a report file exclusively (0600) in the output folder.
func (s *scan) writeOut(name, text string) error {
	f, err := os.OpenFile(filepath.Join(s.out, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	return errors.Join(err, f.Close())
}
