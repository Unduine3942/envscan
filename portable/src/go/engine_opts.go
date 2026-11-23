// engine_opts.go: command-line options (port of es_parse_args, es_usage, es_list_probes,
// es_check_selection and es_in_list in src/sh/90-main.sh).
package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

const implName = "go"

// Actions of the command line.
const (
	actScan    = "scan"
	actList    = "list"
	actVersion = "version"
	actHelp    = "help"
)

type options struct {
	Deep, Net, Redact     bool
	Out                   string
	Only, Skip            string // checked selections (empty = none)
	OnlySet, SkipSet      bool
	TimeoutSec, BudgetSec int64
	Action                string
	Flags                 []string // the arguments as given (run.flags)
}

// usageError is a command-line error: exit 2 with the message and the usage text on stderr.
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }

const usageText = `usage: envscan [options]
  --deep          enable tier "deep" (commands that may raise security alerts)
  --net           enable tier "net" (reachability of proxies and mirrors from local config)
  --out DIR       parent directory for the output folder
  --only IDS      comma-separated probe ids or area wildcards (net.*); others are skipped
  --skip IDS      comma-separated probe ids or area wildcards to skip
  --timeout SEC   per external command (default 15)
  --budget SEC    whole scan (default 600); remaining probes become skipped
  --no-redact     write secrets unredacted
  --list-probes   print every probe with tier, title and footprint, then exit
  --version       print the version and exit
  --help          this help
Writes envscan-<host>-<UTC time>/ (envscan.json, envscan.md, AGENT_BRIEF.md, envscan.log)
and prints its path on stdout. Read-only; the default tier makes no network traffic.
`

func defaultOptions() *options {
	return &options{Redact: true, TimeoutSec: 15, BudgetSec: 600, Action: actScan, Flags: []string{}}
}

// splitArg is the sh normalisation: "-x=v" splits at the first "=", a single dash becomes two.
func splitArg(arg string) (name, val string, hasVal bool) {
	name = arg
	if len(arg) >= 2 && arg[0] == '-' {
		if i := strings.IndexByte(arg[1:], '='); i >= 1 {
			name, val, hasVal = arg[:i+1], arg[i+2:], true
		}
	}
	if !strings.HasPrefix(name, "--") && len(name) >= 2 && name[0] == '-' {
		name = "-" + name
	}
	return name, val, hasVal
}

var flagOnly = map[string]bool{"--deep": true, "--net": true, "--no-redact": true, "--list-probes": true,
	"--version": true, "--help": true, "--h": true}

// parseArgs is es_parse_args (the selections are checked later by checkSelections).
func parseArgs(args []string) (*options, error) {
	o := defaultOptions()
	for i := 0; i < len(args); i++ {
		name, val, hasVal := splitArg(args[i])
		o.Flags = append(o.Flags, args[i])
		if flagOnly[name] && hasVal {
			return nil, &usageError{"option " + name + " takes no value"}
		}
		switch name {
		case "--deep":
			o.Deep = true
		case "--net":
			o.Net = true
		case "--no-redact":
			o.Redact = false
		case "--list-probes":
			o.Action = actList
		case "--version":
			o.Action = actVersion
		case "--help", "--h":
			o.Action = actHelp
		case "--out", "--only", "--skip", "--timeout", "--budget":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, &usageError{args[i] + " needs a value"}
				}
				i++
				val = args[i]
				o.Flags = append(o.Flags, val)
			}
			if err := o.setValue(name, val); err != nil {
				return nil, err
			}
		default:
			return nil, &usageError{"unknown argument: " + args[i]}
		}
	}
	return o, nil
}

func (o *options) setValue(name, val string) error {
	switch name {
	case "--out":
		if val == "" {
			return &usageError{"--out needs a directory"}
		}
		o.Out = val
	case "--only":
		o.Only, o.OnlySet = val, true
	case "--skip":
		o.Skip, o.SkipSet = val, true
	case "--timeout", "--budget":
		n, ok := positiveSeconds(val)
		if !ok {
			return &usageError{name + " needs a positive number of seconds"}
		}
		if name == "--timeout" {
			o.TimeoutSec = n
		} else {
			o.BudgetSec = n
		}
	}
	return nil
}

// positiveSeconds is es_is_num plus -gt 0 (digits only).
func positiveSeconds(s string) (int64, bool) {
	if !allDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > 1<<31 {
		return 0, false
	}
	return n, true
}

// checkSelections is es_check_selection for --only and --skip (in that order).
func (o *options) checkSelections(ids []string) error {
	only, err := checkSelection(o.Only, "--only", o.OnlySet, ids)
	if err != nil {
		return err
	}
	skip, err := checkSelection(o.Skip, "--skip", o.SkipSet, ids)
	if err != nil {
		return err
	}
	o.Only, o.Skip = only, skip
	return nil
}

func checkSelection(list, opt string, given bool, ids []string) (string, error) {
	if list == "" {
		if given {
			return "", &usageError{opt + " needs probe ids"}
		}
		return "", nil
	}
	var sel []string
	for _, part := range strings.Split(list, ",") {
		pat := shTrim(part)
		if pat == "" {
			continue
		}
		if !validPattern(pat) {
			return "", &usageError{fmt.Sprintf("%s: invalid pattern '%s' (allowed: letters, digits, . _ - *)", opt, pat)}
		}
		if !anyMatch(pat, ids) {
			return "", &usageError{fmt.Sprintf("%s: pattern '%s' matches no probe", opt, pat)}
		}
		sel = append(sel, pat)
	}
	if len(sel) == 0 {
		return "", &usageError{opt + " needs probe ids"}
	}
	return strings.Join(sel, ","), nil
}

func validPattern(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == '*'
		if !ok {
			return false
		}
	}
	return true
}

func anyMatch(pat string, ids []string) bool {
	for _, id := range ids {
		if wildMatch(pat, id) {
			return true
		}
	}
	return false
}

// inList is es_in_list: id matches one of the comma-separated patterns.
func inList(id, list string) bool {
	for _, part := range strings.Split(list, ",") {
		if p := shTrim(part); p != "" && wildMatch(p, id) {
			return true
		}
	}
	return false
}

// wildMatch matches a pattern whose only special character is "*" (validPattern).
func wildMatch(pat, s string) bool {
	if !strings.Contains(pat, "*") {
		return pat == s
	}
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return len(s) >= len(last) && strings.HasSuffix(s, last)
}

// shTrim is es_trim: one trailing CR, then blanks and tabs at both ends.
func shTrim(s string) string {
	s = strings.TrimSuffix(s, "\r")
	return strings.Trim(s, " \t")
}

func specProbeIDs() []string {
	ids := make([]string, 0, len(spec.Probes))
	for _, p := range spec.Probes {
		ids = append(ids, p.ID)
	}
	return ids
}

// listProbes is es_list_probes.
func listProbes(w io.Writer) {
	for _, p := range spec.Probes {
		fmt.Fprintf(w, "%s  [%s]  %s\n", p.ID, p.Tier, p.Title)
		for _, f := range p.Footprint {
			if f != "" && f != "-" {
				fmt.Fprintf(w, "    - %s\n", f)
			}
		}
	}
}

func versionLine() string { return spec.Name + " " + spec.Version + " (" + implName + ")" }
