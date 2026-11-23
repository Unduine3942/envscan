package main

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var paIDRe = regexp.MustCompile(`([0-9]+)(?:\(([^)]*)\))?`)

// paIdToFake turns an id output line into Ids plus /etc/passwd and /etc/group lines (names only
// where id printed one): what the Go probe reads instead of running id.
func paIdToFake(t *testing.T, out string) (Ids, string, string) {
	t.Helper()
	var ids Ids
	passwd, group := "", ""
	addGroup := func(n, name string) {
		if name != "" && !strings.Contains(group, ":"+n+":") {
			group += name + ":x:" + n + ":\n"
		}
	}
	out = strings.TrimSpace(strings.SplitN(out, " context=", 2)[0])
	for _, field := range strings.Fields(out) {
		k, v, _ := strings.Cut(field, "=")
		for i, m := range paIDRe.FindAllStringSubmatch(v, -1) {
			n, _ := strconv.Atoi(m[1])
			switch k {
			case "uid":
				ids.UID, ids.EUID = n, n
				if m[2] != "" {
					passwd = m[2] + ":x:" + m[1] + ":0::/home/" + m[2] + ":/bin/bash\n"
				}
			case "gid":
				ids.GID, ids.EGID = n, n
				addGroup(m[1], m[2])
			case "groups":
				if i > 0 || n != ids.GID {
					ids.Groups = append(ids.Groups, n)
				}
				addGroup(m[1], m[2])
			}
		}
	}
	return ids, passwd, group
}

// TestIdentityCommandCases: the Linux id cases of tests/data/commands.json.
func TestIdentityCommandCases(t *testing.T) {
	for _, c := range paCommandCases(t, "id") {
		name := c["name"].(string)
		if !strings.HasPrefix(name, "linux_") && !strings.HasPrefix(name, "openshift") && name != "solaris_no_groups_field" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ids, passwd, group := paIdToFake(t, c["output"].(string))
			e := newFakeEnv(t, paTree(t, map[string]string{"etc/passwd": passwd, "etc/group": group}))
			e.IdsV = ids
			r := paRun(t, e, "user.identity")
			f := paJSONPlain(c["facts"]).(map[string]any)
			groups := f["groups"]
			if name == "solaris_no_groups_field" {
				groups = []any{f["primary_group"]} // Linux id always lists the primary group
			}
			paWant(t, r, map[string]any{"name": f["name"], "uid": f["uid"], "gid": f["gid"],
				"primary_group": f["primary_group"], "groups": groups, "is_admin": f["is_admin"]})
		})
	}
}

func TestIdentityDetails(t *testing.T) {
	root := paTree(t, map[string]string{
		"etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000:Bob:/home/bob:/bin/zsh\n",
		"etc/group":  "bob:x:1000:\nsudo:x:27:bob\ndocker:x:999:bob\n",
	})
	e := newFakeEnv(t, root)
	e.IdsV = Ids{UID: 1000, EUID: 1000, GID: 1000, EGID: 1000, Groups: []int{1000, 27, 999, 4242}}
	e.Vars = map[string]string{"HOME": "/home/bob", "SHELL": "/bin/bash", "USER": "ignored"}
	e.PathBins["sudo"] = "/usr/bin/sudo"
	r := paRun(t, e, "user.identity")
	paWant(t, r, map[string]any{"name": "bob", "groups": []any{"bob", "sudo", "docker", "4242"},
		"privileged_groups": []any{"sudo", "docker"}, "elevation_method": "sudo", "passwd_home": "/home/bob",
		"passwd_shell": "/bin/zsh", "passwd_entry": true, "home": "/home/bob", "shell": "/bin/bash", "sid": nil, "domain": nil})
	if r.Status != StOK || r.Facts["admin_groups"] != "sudo\ndocker\n" || r.Facts["is_admin"] != "false" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
	e.IdsV = Ids{UID: 1234, EUID: 1234, GID: 1234, EGID: 1234}
	e.Vars["USER"] = "ann@corp.example"
	delete(e.PathBins, "sudo")
	e.PathBins["doas"] = "/usr/bin/doas"
	r = paRun(t, e, "user.identity")
	paWant(t, r, map[string]any{"name": "ann@corp.example", "domain": "corp.example", "passwd_entry": false,
		"primary_group": "1234", "elevation_method": "doas (present)"})
	r = paRun(t, newFakeEnv(t, ""), "user.identity")
	paWant(t, r, map[string]any{"passwd_entry": nil, "is_admin": true})
	if !paHasNote(r, "could not be checked") || len(e.Ran) != 0 {
		t.Errorf("notes %v ran %v", r.Notes, e.Ran)
	}
}

func TestIdentityNeverRunsIdOrGetent(t *testing.T) {
	e := paLinux(t)
	e.PathBins["id"], e.PathBins["getent"] = "/usr/bin/id", "/usr/bin/getent"
	paRun(t, e, "user.identity")
	if len(e.Ran) != 0 {
		t.Errorf("ran %v", e.Ran)
	}
}

func TestProfile(t *testing.T) {
	root := paTree(t, map[string]string{"home/bob/.config/user-dirs.dirs": "# x\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\n" +
		"XDG_DOWNLOAD_DIR=\"$HOME/dl\"\nXDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\n"})
	e := newFakeEnv(t, root)
	e.MountTab = []Mount{{"/dev/sda1", "/", "ext4", "rw"}, {"srv:/home", "/net", "nfs4", "rw"}}
	e.NetPaths = []string{"/net"}
	e.Vars = map[string]string{"HOME": "/home/bob", "XDG_RUNTIME_DIR": "/run/user/1000"}
	r := paRun(t, e, "user.profile")
	paWant(t, r, map[string]any{"home": "/home/bob", "home_exists": true, "home_writable": true, "home_fstype": "ext4",
		"home_network": false, "profile_type": "local", "xdg": map[string]any{"XDG_RUNTIME_DIR": "/run/user/1000"},
		"redirected_folders": map[string]any{"XDG_DESKTOP_DIR": "$HOME/Schreibtisch", "XDG_DOWNLOAD_DIR": "$HOME/dl"},
		"onedrive":           nil})
	keys := mustGet(r, "redirected_folders").(*Obj).Keys()
	if !reflect.DeepEqual(keys, []string{"XDG_DESKTOP_DIR", "XDG_DOWNLOAD_DIR"}) || r.Facts["home_fstype"] != "ext4" {
		t.Errorf("keys %v facts %v", keys, r.Facts)
	}
	e.Vars["HOME"] = "/net/bob"
	r = paRun(t, e, "user.profile")
	paWant(t, r, map[string]any{"home_exists": nil, "home_network": true, "profile_type": "network", "home_fstype": "nfs4",
		"redirected_folders": nil})
	e.Vars["HOME"] = "/home/missing"
	e.RefusedP["/home/missing"] = "credential store"
	r = paRun(t, e, "user.profile")
	if !paHasNote(r, "not tested") {
		t.Errorf("refused HOME: %v", r.Notes)
	}
	e.Vars = map[string]string{}
	if r := paRun(t, e, "user.profile"); r.Status != StPartial {
		t.Errorf("no HOME: %s", r.Status)
	}
}

func TestPrivileges(t *testing.T) {
	e := newFakeEnv(t, "")
	r := paRun(t, e, "user.privileges")
	if r.Status != StNotFound || mustGet(r, "sudo_rules") != nil {
		t.Errorf("no sudo: %s", r.Status)
	}
	e.PathBins["sudo"] = "/usr/bin/sudo"
	e.Cmds["sudo -n -l"] = fakeCmd{Stdout: "Matching Defaults entries for bob on h:\n    env_reset\n\n" +
		"User bob may run the following commands on h:\n    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/apt\n"}
	r = paRun(t, e, "user.privileges")
	paWant(t, r, map[string]any{"exit_code": "0", "password_required": false, "nopasswd_rules": true,
		"sudo_rules": []any{"(ALL : ALL) ALL", "(root) NOPASSWD: /usr/bin/apt"}})
	e.Cmds["sudo -n -l"] = fakeCmd{Stderr: "sudo: a password is required\n", Exit: 1}
	r = paRun(t, e, "user.privileges")
	paWant(t, r, map[string]any{"exit_code": "1", "password_required": true, "sudo_rules": []any{}, "nopasswd_rules": false})
	if _, ok := r.Raw.Get("sudo_n_l"); !ok || !paHasNote(r, "may be logged") {
		t.Errorf("raw/notes %v", r.Notes)
	}
}
