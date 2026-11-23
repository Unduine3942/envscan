// pa_time.go: os.time_locale and os.health (ports of src/sh/20-os.sh, Linux branches).
package main

import (
	"regexp"
	"strconv"
	"strings"
)

func probeOSTimeLocale(e Env, r *Result) {
	r.Src("environment TZ, LANG, LC_*")
	tz, _ := e.Getenv("TZ")
	if tz == "" {
		if l, ok := readFirstLine(e, r, "/etc/timezone"); ok {
			tz = l
		}
	}
	if tz == "" {
		if fi, err := e.Lstat("/etc/localtime"); err == nil && fi.Type == TypeLink {
			r.Src("read /etc/localtime link target")
			rp, _ := paResolve(e, "/etc/localtime")
			if strings.Contains(rp, "/zoneinfo/") {
				tz = rp[strings.LastIndex(rp, "/zoneinfo/")+len("/zoneinfo/"):]
			}
		}
	}
	off := paUTCOffset(e, r)
	loc, locsrc := paLocaleName(e)
	lc := paLocaleCmds(e, r, loc, locsrc)
	enc := lc.enc
	if enc == "" {
		enc = paEncodingOf(lc.loc)
	}
	isu8 := "false"
	if l := strings.ToLower(enc); l == "utf-8" || l == "utf8" {
		isu8 = "true"
	}
	d := r.Data
	d.Set("timezone", strOrNil(tz)).Set("utc_offset", strOrNil(off)).Set("locale", lc.loc).Set("locale_source", lc.src)
	d.Set("locale_env", paLocaleEnv(e)).Set("encoding", strOrNil(enc)).Set("encoding_is_utf8", boolOrNil(isu8))
	d.Set("utf8_available", boolOrNil(lc.u8)).Set("decimal_separator", strOrNil(lc.dec)).Set("date_format", strOrNil(lc.dfmt))
	d.Set("codepage_ansi", nil).Set("codepage_oem", nil).Set("codepage_console", nil)
	for k, v := range map[string]string{"utc_offset": off, "encoding": enc, "encoding_utf8": isu8, "decimal_sep": lc.dec,
		"locale_name": lc.loc, "timezone": tz} {
		r.Fact(k, v)
	}
}

// paUTCOffset is sh "date +%z": the offset of the scanner's clock in the local zone. Go loads the
// zone from TZ or /etc/localtime like the C library, except for a POSIX TZ rule ("JST-9"), which
// Go does not parse (it falls back to UTC): then date +%z runs when present.
func paUTCOffset(e Env, r *Result) string {
	now := e.Now()
	tz, set := e.Getenv("TZ")
	tz = strings.TrimPrefix(tz, ":")
	goFellBack := set && tz != "" && now.Location().String() == "UTC" && !paUTCName(tz)
	if !goFellBack {
		r.Src("clock: local UTC offset (zone from TZ or /etc/localtime)")
		return now.Format("-0700")
	}
	c := tool(e, r, RunOpt{}, "date", "+%z")
	off, _ := paFirstLine(c.Stdout)
	if c.Exit != 0 || !paOffsetRe.MatchString(off) {
		if c.Exit == 127 {
			r.Note("TZ=%s is a rule the scanner cannot evaluate and date is not available: UTC offset unknown", tz)
		}
		return ""
	}
	return off
}

var paOffsetRe = regexp.MustCompile(`^[+-][0-9]{4}$`)

func paUTCName(tz string) bool {
	switch strings.TrimPrefix(strings.TrimPrefix(tz, "posix/"), "Etc/") {
	case "UTC", "UCT", "Universal", "Zulu", "GMT", "GMT0", "GMT+0", "GMT-0", "Greenwich", "UTC0":
		return true
	}
	return false
}

// paLocaleName: the original LC_ALL, else LC_CTYPE, else LANG (sh es_loc).
func paLocaleName(e Env) (string, string) {
	for _, n := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v, _ := e.Getenv(n); v != "" {
			return v, "environment"
		}
	}
	return "C", "default"
}

type paLocale struct{ loc, src, enc, dec, dfmt, u8 string }

// paLocaleCmds runs the locale commands with the user's locale (sh ES_CHILD_LOCALE=user).
func paLocaleCmds(e Env, r *Result, loc, src string) paLocale {
	lc := paLocale{loc: loc, src: src}
	opt := RunOpt{UserLocale: true}
	c := tool(e, r, opt, "locale")
	if c.Exit != 0 {
		r.Partial("the locale command is not available; encoding derived from the locale name")
		return lc
	}
	r.SetRaw("locale", c.Stdout)
	if src == "default" {
		for _, l := range lines(c.Stdout) {
			if v, ok := strings.CutPrefix(l, "LC_CTYPE="); ok && paUnquote(v) != "" {
				lc.loc, lc.src = paUnquote(v), "locale command (LC_CTYPE)"
			}
		}
	}
	if c := tool(e, r, opt, "locale", "charmap"); c.Exit == 0 {
		lc.enc, _ = paFirstLine(c.Stdout)
	}
	if c := tool(e, r, opt, "locale", "-k", "decimal_point", "d_fmt"); c.Exit == 0 {
		for _, l := range lines(c.Stdout) {
			if v, ok := strings.CutPrefix(l, "decimal_point="); ok {
				lc.dec = paUnquote(v)
			} else if v, ok := strings.CutPrefix(l, "d_fmt="); ok {
				lc.dfmt = paUnquote(v)
			}
		}
	}
	if c := tool(e, r, opt, "locale", "-a"); c.Exit == 0 {
		lc.u8 = "false"
		if paUTF8Re.MatchString(c.Stdout) {
			lc.u8 = "true"
		}
	}
	return lc
}

var paUTF8Re = regexp.MustCompile(`(?i)utf-*8`)

// paEncodingOf: the codeset of a locale name (ll_CC.codeset@modifier), ANSI_X3.4-1968 for C/POSIX.
func paEncodingOf(loc string) string {
	if _, after, ok := strings.Cut(loc, "."); ok {
		enc, _, _ := strings.Cut(after, "@")
		return enc
	}
	if loc == "C" || loc == "POSIX" {
		return "ANSI_X3.4-1968"
	}
	return ""
}

func paLocaleEnv(e Env) *Obj {
	o := NewObj()
	for _, n := range []string{"LANG", "LANGUAGE", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_ALL"} {
		if v, _ := e.Getenv(n); v != "" {
			o.Set(n, v)
		}
	}
	return o
}

// ---------------------------------------------------------------- os.health

func probeOSHealth(e Env, r *Result) {
	up, l1, l5, l15 := "", "", "", ""
	if l, ok := readFirstLine(e, r, "/proc/uptime"); ok {
		up = l[:strings.IndexAny(l+" ", ". ")]
	}
	if l, ok := readFirstLine(e, r, "/proc/loadavg"); ok {
		f := append(strings.Fields(l), "", "", "")
		l1, l5, l15 = f[0], f[1], f[2]
	}
	if up == "" {
		up, l1, l5, l15 = paUptimeCmd(e, r, l1, l5, l15)
	}
	boot := ""
	if paIsNum(up) {
		n, _ := strconv.ParseInt(up, 10, 64)
		boot = paISO(e.Now().Unix() - n)
	} else {
		up = ""
		r.Partial("uptime could not be determined")
	}
	pr, reasons := paPendingReboot(e, r)
	d := r.Data
	d.Set("uptime_seconds", num(up)).Set("last_boot_utc", strOrNil(boot))
	if l1 != "" {
		d.Set("load", []any{num(l1), num(l5), num(l15)})
	} else {
		d.Set("load", nil)
	}
	d.Set("pending_reboot", boolOrNil(pr)).Set("pending_reasons", nonEmptyLines(reasons))
	r.Fact("pending_reboot", pr)
	r.Fact("pending_reasons", reasons)
	r.Fact("uptime_s", up)
}

var (
	paUpDaysRe = regexp.MustCompile(`[0-9]+ +days?`)
	paUpHMRe   = regexp.MustCompile(`[0-9]+:[0-9]+`)
	paUpMinRe  = regexp.MustCompile(`[0-9]+ +min`)
	paUpHrsRe  = regexp.MustCompile(`[0-9]+ +hrs?`)
	paUpHeadRe = regexp.MustCompile(`^.* up +`)
	paUpUsers  = regexp.MustCompile(`, +[0-9]+ users?.*$`)
	paUpLoadRe = regexp.MustCompile(`^.*load averages?: *`)
)

// paUptimeCmd is the sh fallback for systems without /proc/uptime: parse "uptime".
func paUptimeCmd(e Env, r *Result, l1, l5, l15 string) (string, string, string, string) {
	c := tool(e, r, RunOpt{}, "uptime")
	first, ok := paFirstLine(c.Stdout)
	if c.Exit != 0 || !ok {
		return "", l1, l5, l15
	}
	r.SetRaw("uptime", c.Stdout)
	s := paUpUsers.ReplaceAllString(paUpHeadRe.ReplaceAllString(first, ""), "")
	t := 0
	lead := func(m string) int { n, _ := strconv.Atoi(strings.Fields(m)[0]); return n }
	if m := paUpDaysRe.FindString(s); m != "" {
		t += lead(m) * 86400
	}
	if m := paUpHMRe.FindString(s); m != "" {
		h, mm, _ := strings.Cut(m, ":")
		hn, _ := strconv.Atoi(h)
		mn, _ := strconv.Atoi(mm)
		t += hn*3600 + mn*60
	} else if m := paUpMinRe.FindString(s); m != "" {
		t += lead(m) * 60
	} else if m := paUpHrsRe.FindString(s); m != "" {
		t += lead(m) * 3600
	}
	if loc := paUpLoadRe.FindStringIndex(first); loc != nil {
		f := append(strings.Fields(strings.ReplaceAll(first[loc[1]:], ",", " ")), "", "", "")
		l1, l5, l15 = f[0], f[1], f[2]
	}
	return strconv.Itoa(t), l1, l5, l15
}

// paPendingReboot: the reboot-required flag files and the installed kernels in /lib/modules.
func paPendingReboot(e Env, r *Result) (string, string) {
	pr, reasons := "", ""
	if e.Exists("/var/run/reboot-required") || e.Exists("/run/reboot-required") {
		pr, reasons = "true", "reboot-required flag file present\n"
		for _, f := range []string{"/var/run/reboot-required.pkgs", "/run/reboot-required.pkgs"} {
			if text, _, err := e.ReadText(f, 1<<20); err == nil {
				reasons += "packages: " + strings.Join(lines(text), " ") + "\n"
				break
			}
		}
	}
	r.Src("read /var/run/reboot-required")
	if e.OS() != "linux" || !paIsDir(e, "/lib/modules") {
		return pr, reasons
	}
	r.Src("list /lib/modules (installed kernels)")
	newest := paNewestKernel(e)
	if newest == "" {
		return pr, reasons
	}
	if pr == "" {
		pr = "false"
	}
	running := paUname(e).Release
	if !paIsDir(e, "/lib/modules/"+running) {
		pr, reasons = "true", reasons+"modules of the running kernel "+running+" are no longer installed\n"
	} else if newest != running && paVercmp(newest, running) == 1 {
		pr, reasons = "true", reasons+"newer kernel installed: "+newest+" (running "+running+")\n"
	}
	return pr, reasons
}

func paNewestKernel(e Env) string {
	ents, _, err := e.ReadDir("/lib/modules", 0)
	if err != nil {
		return ""
	}
	newest := ""
	for _, d := range ents {
		if d.Type != TypeDir && !(d.Type == TypeLink && paIsDir(e, "/lib/modules/"+d.Name)) {
			continue
		}
		if newest == "" || paVercmp(d.Name, newest) == 1 {
			newest = d.Name
		}
	}
	return newest
}
