// pa_user.go: user.identity, user.privileges (ports of src/sh/22-user.sh, Linux branches).
//
// user.identity: sh runs id (names through NSS) and getent passwd <uid>. Go asks the kernel for
// the ids (Env.Ids: getuid/getgid/getgroups) and takes names only from /etc/passwd and
// /etc/group (own uid and groups only); it never makes NSS lookups (LDAP/SSSD users and groups
// that are not in those files have no name here: the user name falls back to USER/LOGNAME and a
// group to its number, as id prints it when it finds no name).
package main

import (
	"regexp"
	"strconv"
	"strings"
)

func init() {
	registerProbe("user.identity", probeUserIdentity)
	registerProbe("user.profile", probeUserProfile)
	registerProbe("user.privileges", probeUserPrivileges)
}

// paGroupNames: gid -> name from /etc/group (first entry wins, like getgrgid on files).
func paGroupNames(e Env, r *Result) map[int]string {
	names := map[int]string{}
	text, _, err := e.ReadText("/etc/group", 4<<20)
	if err != nil {
		return names
	}
	r.Src("read /etc/group (names of own groups only)")
	for _, l := range lines(text) {
		f := strings.Split(l, ":")
		if len(f) < 3 {
			continue
		}
		if g, err := strconv.Atoi(f[2]); err == nil {
			if _, dup := names[g]; !dup {
				names[g] = f[0]
			}
		}
	}
	return names
}

// paPasswdEntry: the /etc/passwd line of UID (ok=false when the file cannot be read).
func paPasswdEntry(e Env, r *Result, uid int) ([]string, bool) {
	text, _, err := e.ReadText("/etc/passwd", 4<<20)
	if err != nil {
		return nil, false
	}
	r.Src("read /etc/passwd (own uid only)")
	for _, l := range lines(text) {
		f := strings.Split(l, ":")
		if len(f) >= 3 && f[2] == strconv.Itoa(uid) {
			for len(f) < 7 {
				f = append(f, "")
			}
			return f, true
		}
	}
	return nil, true
}

// paIdGroups is the group list in id's order: real gid, effective gid, then the others.
func paIdGroups(ids Ids) []int {
	out := []int{ids.GID}
	if ids.EGID != ids.GID {
		out = append(out, ids.EGID)
	}
	for _, g := range ids.Groups {
		if !paHasInt(out, g) {
			out = append(out, g)
		}
	}
	return out
}

var paAdminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true, "root": true, "adm": true,
	"staff": true, "docker": true, "lxd": true, "libvirt": true, "Administrators": true}

func probeUserIdentity(e Env, r *Result) {
	ids := e.Ids()
	r.Src("syscall getuid, getgid, getgroups")
	gnames := paGroupNames(e, r)
	gname := func(g int) string { return paOr(gnames[g], strconv.Itoa(g)) }
	pw, pwok := paPasswdEntry(e, r, ids.UID)
	user := ""
	if pw != nil {
		user = pw[0]
	}
	if user == "" {
		user = paOr(paEnv(e, "USER"), paEnv(e, "LOGNAME"))
	}
	r.Src("environment HOME, SHELL, USER, LOGNAME")
	groups, adm := []any{}, ""
	for _, g := range paIdGroups(ids) {
		n := gname(g)
		groups = append(groups, n)
		if paAdminGroups[n] {
			adm += n + "\n"
		}
	}
	pwe, pwhome, pwshell := "", "", ""
	switch {
	case pw != nil:
		pwe, pwhome, pwshell = "true", pw[5], pw[6]
	case pwok:
		pwe = "false"
	default:
		r.Note("the passwd database could not be checked on this system")
	}
	admin := strconv.FormatBool(ids.UID == 0)
	dom := ""
	if _, after, ok := strings.Cut(user, "@"); ok {
		dom = after
	}
	d := r.Data
	d.Set("name", user).Set("domain", strOrNil(dom)).Set("uid", ids.UID).Set("gid", ids.GID)
	d.Set("primary_group", strOrNil(gname(ids.GID))).Set("groups", groups).Set("privileged_groups", nonEmptyLines(adm))
	d.Set("sid", nil).Set("is_admin", boolOrNil(admin)).Set("elevation_method", strOrNil(paElevation(e, adm)))
	d.Set("integrity", nil).Set("home", strOrNil(paEnv(e, "HOME"))).Set("passwd_home", strOrNil(pwhome))
	d.Set("shell", strOrNil(paEnv(e, "SHELL"))).Set("passwd_shell", strOrNil(pwshell)).Set("passwd_entry", boolOrNil(pwe))
	r.Fact("user", user)
	r.Fact("uid", strconv.Itoa(ids.UID))
	r.Fact("is_admin", admin)
	r.Fact("passwd_entry", pwe)
	r.Fact("admin_groups", adm)
}

func paEnv(e Env, n string) string { v, _ := e.Getenv(n); return v }

func paElevation(e Env, adm string) string {
	for _, g := range []string{"sudo", "wheel", "admin"} {
		if strings.Contains("\n"+adm, "\n"+g+"\n") {
			if _, ok := e.Which("sudo"); ok {
				return "sudo"
			}
			break
		}
	}
	if _, ok := e.Which("doas"); ok {
		return "doas (present)"
	}
	return ""
}

// ---------------------------------------------------------------- user.privileges

var paSudoPwRe = regexp.MustCompile(`(?i)password is required|a terminal is required|askpass`)

func probeUserPrivileges(e Env, r *Result) {
	if _, ok := e.Which("sudo"); !ok {
		r.SetStatus(StNotFound, "sudo is not installed")
		r.Data.Set("sudo_rules", nil)
		return
	}
	c, out := paRunBoth(e, r, "sudo", "-n", "-l")
	r.SetRaw("sudo_n_l", out)
	pwreq := paSudoPwRe.MatchString(out)
	rules, on := "", false
	for _, l := range lines(out) {
		if on && strings.TrimSpace(l) != "" {
			rules += strings.TrimLeft(l, " \t") + "\n"
		}
		if strings.Contains(l, "may run the following commands") {
			on = true
		}
	}
	list := paListLines(rules, 100, paLine)
	d := r.Data
	d.Set("exit_code", c.Exit).Set("password_required", pwreq).Set("sudo_rules", list)
	d.Set("nopasswd_rules", strings.Contains(rules, "NOPASSWD"))
	r.Note("sudo -n -l may be logged by the system (auth log)")
}
