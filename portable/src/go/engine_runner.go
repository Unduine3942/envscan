// engine_runner.go: the probe runner (port of es_run_all / es_run_one / es_progress /
// es_netskip_note). Probes run one after another in spec order, each in its own goroutine with
// panic recovery and a time cap (240 s, tools.inventory 600 s, never past the scan budget). A
// probe over its cap becomes "timeout": its context is cancelled (its running child is killed)
// and whatever it still does goes to a result nobody reads. Facts are published only for ok and
// partial probes.
package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	probeCapDefault = 240 * time.Second
	probeCapLong    = 600 * time.Second
	longProbeID     = "tools.inventory"
)

// runRecord is one row of results.tsv: the probe, its result, duration and skip kind.
type runRecord struct {
	N     int
	Probe SpecProbe
	Res   *Result
	DurMS int64
	Kind  string // "-", "tier", "select" or "budget"
}

type runner struct {
	e        *realEnv
	opts     *options
	funcs    map[string]probeFunc
	probes   []SpecProbe
	stderr   io.Writer
	capShort time.Duration
	capLong  time.Duration
}

func newRunner(e *realEnv, stderr io.Writer) *runner {
	return &runner{e: e, opts: e.opts, funcs: probeFuncs, probes: spec.Probes, stderr: stderr,
		capShort: probeCapDefault, capLong: probeCapLong}
}

// say is es_say: a line on stderr and in the log.
func (rn *runner) say(msg string) {
	fmt.Fprintln(rn.stderr, msg)
	rn.e.Log(msg)
}

func tiersText(o *options) string {
	t := "default"
	if o.Deep {
		t += ", deep"
	}
	if o.Net {
		t += ", net"
	}
	return t
}

func (rn *runner) runAll(out string) []*runRecord {
	rn.say(fmt.Sprintf("%s %s (%s): %d probes, tiers %s -> %s", spec.Name, spec.Version, implName,
		len(rn.probes), tiersText(rn.opts), out))
	recs := make([]*runRecord, 0, len(rn.probes))
	for i, p := range rn.probes {
		recs = append(recs, rn.runOne(i+1, p))
	}
	return recs
}

func (rn *runner) runOne(n int, p SpecProbe) *runRecord {
	rec := &runRecord{N: n, Probe: p, Kind: "-"}
	why, kind, left := rn.skipWhy(p)
	if why != "" {
		r := newResult(p.ID)
		r.SetStatus(StSkipped, why)
		rec.Res, rec.Kind = r, kind
	} else {
		rec.Res, rec.DurMS = rn.execute(p, rn.capFor(p.ID, left))
	}
	if rec.Res.Status == StOK || rec.Res.Status == StPartial {
		rn.e.publishFacts(rec.Res.Facts)
	}
	rn.progress(n, p.ID, rec.Res.Status, rec.DurMS)
	return rec
}

// skipWhy: tier, selection and budget rules of es_run_one; left = whole seconds of budget left.
func (rn *runner) skipWhy(p SpecProbe) (why, kind string, left int64) {
	o := rn.opts
	switch {
	case p.Tier == "deep" && !o.Deep:
		return "tier deep is not enabled (use --deep)", "tier", 0
	case p.Tier == "net" && !o.Net:
		return "tier net is not enabled (use --net)", "tier", 0
	case o.Only != "" && !inList(p.ID, o.Only):
		return "not selected by --only", "select", 0
	case o.Skip != "" && inList(p.ID, o.Skip):
		return "excluded by --skip", "select", 0
	}
	left = int64(rn.e.deadline.Sub(rn.e.clock()) / time.Second)
	if left < 1 {
		return fmt.Sprintf("scan budget of %ds exhausted", o.BudgetSec), "budget", left
	}
	return "", "", left
}

func (rn *runner) capFor(id string, left int64) time.Duration {
	c := rn.capShort
	if id == longProbeID {
		c = rn.capLong
	}
	if l := time.Duration(left) * time.Second; l < c {
		c = l
	}
	return c
}

// execute runs one probe function with panic recovery and its time cap.
func (rn *runner) execute(p SpecProbe, limit time.Duration) (*Result, int64) {
	start := time.Now()
	f, ok := rn.funcs[p.ID]
	if !ok {
		r := newResult(p.ID)
		r.Fail(fmt.Sprintf("probe function probe_%s is missing", strings.Replace(p.ID, ".", "_", 1)))
		return r, time.Since(start).Milliseconds()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pe := &probeEnv{realEnv: rn.e, ctx: ctx}
	r := newResult(p.ID)
	done := make(chan struct{})
	go runProbeFunc(f, pe, r, done)
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		pe.logSkips(p.ID)
	case <-timer.C:
		cancel()
		pe.removeMade()
		r = newResult(p.ID)
		r.Status = StTimeout
		r.Note("probe stopped after %ds (per-probe time cap or scan budget)", int64(limit/time.Second))
	}
	return r, time.Since(start).Milliseconds()
}

func runProbeFunc(f probeFunc, e Env, r *Result, done chan struct{}) {
	defer close(done)
	defer func() {
		if v := recover(); v != nil {
			r.Fail(fmt.Sprintf("probe ended unexpectedly (panic: %v)", v))
		}
	}()
	f(e, r)
}

// progress is es_progress.
func (rn *runner) progress(n int, id, status string, durMS int64) {
	pad := " "
	if len(id) < 33 {
		pad += strings.Repeat(".", 33-len(id))
	}
	line := fmt.Sprintf("[%2d/%d] %s%s %-9s %6d ms", n, len(rn.probes), id, pad, status, durMS)
	rn.say(line)
}

// probeEnv is the Env one probe gets: its commands die with its context, and what Glob left
// out is collected for the notes.
type probeEnv struct {
	*realEnv
	ctx      context.Context
	mu       sync.Mutex
	netSkip  []string
	credSkip []string
	made     []string // folders this probe made (MkdirUnique)
	ended    bool     // the probe timed out: its folders are removed, no new ones
}

// MkdirUnique records the folders of the probe, so that they can be removed when it times out.
func (p *probeEnv) MkdirUnique(parent string) (string, error) {
	if p.ctx.Err() != nil {
		return "", stoppingRefusal(parent)
	}
	d, err := p.realEnv.MkdirUnique(parent)
	if err != nil {
		return d, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		_ = p.realEnv.RemoveOwn(d)
		return "", stoppingRefusal(parent)
	}
	p.made = append(p.made, d)
	return d, nil
}

// removeMade removes the folders a timed-out probe made (those it removed itself are skipped).
func (p *probeEnv) removeMade() {
	p.mu.Lock()
	p.ended = true
	made := p.made
	p.made = nil
	p.mu.Unlock()
	for _, d := range made {
		_ = p.realEnv.RemoveOwn(d)
	}
}

func (p *probeEnv) Run(opt RunOpt, path string, args ...string) CmdResult {
	return p.realEnv.runCtx(p.ctx, opt, path, args)
}

func (p *probeEnv) Glob(pattern string) ([]string, error) {
	return p.realEnv.globRec(pattern, p.record)
}

func (p *probeEnv) record(path string, credLink bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if credLink {
		p.credSkip = append(p.credSkip, path)
	} else {
		p.netSkip = append(p.netSkip, path)
	}
}

// logSkips writes what Glob left out to envscan.log (sh es_netskip_note made probe notes of
// it; here the probes write their own notes from the *Refusal errors, so the engine only logs).
func (p *probeEnv) logSkips(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range dedupKeepOrder(p.credSkip) {
		p.realEnv.Log(id + ": " + s + " not read: link to a credential store")
	}
	ns := dedupKeepOrder(p.netSkip)
	if len(ns) == 0 {
		return
	}
	l := strings.Join(ns[:min(5, len(ns))], ", ")
	if len(ns) > 5 {
		l += fmt.Sprintf(" and %d more", len(ns)-5)
	}
	p.realEnv.Log(id + ": not read because they are on network or autofs mounts (nothing there is touched): " + l)
}

func dedupKeepOrder(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var _ Env = (*probeEnv)(nil)
var _ Env = (*realEnv)(nil)
