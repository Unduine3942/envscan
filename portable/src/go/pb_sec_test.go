package main

import (
	"testing"
	"time"
)

func TestSecAppControlLinux(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{
		"/sys/fs/selinux/enforce":                 "1\n",
		"/etc/selinux/config":                     "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
		"/sys/module/apparmor/parameters/enabled": "N\n",
		"/proc/self/attr/current":                 "system_u:system_r:unconfined_t:s0\x00",
		"/proc/self/status":                       "Name:\tx\nSeccomp:\t2\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n",
		"/sys/kernel/security/lockdown":           "none [integrity] confidentiality\n",
	})
	pbMkdir(t, e.Root, "/etc/fapolicyd")
	e.PathBins["systemctl"] = "/usr/bin/systemctl"
	e.Cmds["systemctl is-active fapolicyd"] = fakeCmd{Stdout: "inactive\n", Exit: 3}
	e.MountTab = []Mount{{Device: "/dev/sda1", Dir: "/", Type: "ext4", Options: "ro,relatime"}}
	r := pbRun(e, "sec.app_control")
	d := r.Data
	pbKeys(t, d, "applocker", "srp", "wdac", "smart_app_control", "exploit_protection", "selinux", "selinux_config",
		"selinux_context", "apparmor", "apparmor_profile", "fapolicyd", "seccomp", "no_new_privs", "cap_eff",
		"lockdown", "root_readonly", "sip", "gatekeeper", "mdm_enrolled")
	pbEq(t, "selinux", d.Str("selinux"), "enforcing")
	pbEq(t, "selinux_config", d.Str("selinux_config"), "enforcing")
	pbEq(t, "context", d.Str("selinux_context"), "system_u:system_r:unconfined_t:s0")
	pbEq(t, "apparmor", d.Str("apparmor"), "disabled")
	pbEq(t, "fapolicyd installed", pbGet(t, d, "fapolicyd", "installed"), true)
	pbEq(t, "fapolicyd state", pbGet(t, d, "fapolicyd", "state"), "inactive")
	pbEq(t, "seccomp", d.Str("seccomp"), "filter")
	pbEq(t, "nnp", pbGet(t, d, "no_new_privs"), true)
	pbEq(t, "lockdown", d.Str("lockdown"), "integrity")
	pbEq(t, "root ro", pbGet(t, d, "root_readonly"), true)
	pbEq(t, "status", r.Status, StOK)
	pbEq(t, "fact root_ro", r.Facts["root_ro"], "true")
	pbEq(t, "fact selinux", r.Facts["selinux"], "enforcing")
}

func TestSecAppControlAppArmorProfileAndDistroless(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{
		"/sys/module/apparmor/parameters/enabled": "Y\n",
		"/proc/self/attr/apparmor/current":        "docker-default (enforce)\n",
		"/etc/selinux/config":                     "SELINUX=permissive\n",
		"/proc/self/status":                       "Seccomp:\t7\nNoNewPrivs:\t0\n",
	})
	r := pbRun(e, "sec.app_control")
	pbEq(t, "profile", r.Data.Str("apparmor_profile"), "docker-default (enforce)")
	pbEq(t, "selinux (config only)", r.Data.Str("selinux"), "disabled")
	pbEq(t, "seccomp raw", r.Data.Str("seccomp"), "7")
	pbEq(t, "nnp", pbGet(t, r.Data, "no_new_privs"), false)

	empty := pbNewEnv(t)
	r2 := pbRun(empty, "sec.app_control")
	pbEq(t, "distroless status", r2.Status, StOK)
	pbEq(t, "distroless selinux", pbGet(t, r2.Data, "selinux"), nil)
	pbEq(t, "distroless root ro", pbGet(t, r2.Data, "root_readonly"), nil)
	if len(empty.Ran) != 0 {
		t.Errorf("ran %v", empty.Ran)
	}
}

const pbOpensslA = "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)\nbuilt on: x\n" +
	"platform: linux-x86_64\nOPENSSLDIR: \"/usr/lib/ssl\"\nENGINESDIR: \"/usr/lib/x86_64-linux-gnu/engines-3\"\n"

func TestSecCrypto(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{
		"/proc/sys/crypto/fips_enabled": "1\n",
		"/etc/crypto-policies/config":   "# set by admin\n\nFIPS\r\n",
	})
	e.PathBins["openssl"] = "/usr/bin/openssl"
	e.Cmds["openssl version -a"] = fakeCmd{Stdout: pbOpensslA}
	e.Vars["OPENSSL_CONF"] = "/etc/ssl/custom.cnf"
	r := pbRun(e, "sec.crypto")
	pbKeys(t, r.Data, "fips", "crypto_policy", "openssl_version", "openssl_dir", "openssl_conf", "schannel", "dotnet_strong_crypto")
	pbEq(t, "fips", pbGet(t, r.Data, "fips"), true)
	pbEq(t, "policy", r.Data.Str("crypto_policy"), "FIPS")
	pbEq(t, "version", r.Data.Str("openssl_version"), "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)")
	pbEq(t, "dir", r.Data.Str("openssl_dir"), "/usr/lib/ssl")
	pbEq(t, "conf", r.Data.Str("openssl_conf"), "/etc/ssl/custom.cnf")
	if _, ok := r.Raw.Get("openssl"); !ok {
		t.Error("raw openssl missing")
	}
	pbEq(t, "fact fips", r.Facts["fips"], "true")

	d := pbNewEnv(t)
	d.PathBins["openssl"] = "/usr/bin/openssl"
	d.Cmds["openssl version -a"] = fakeCmd{Exit: 1}
	r2 := pbRun(d, "sec.crypto")
	pbEq(t, "absent fips", pbGet(t, r2.Data, "fips"), false)
	pbEq(t, "partial", r2.Status, StPartial)
	if !pbHasNote(r2, "kernel without FIPS support") || !pbHasNote(r2, "openssl version -a failed") {
		t.Errorf("notes %v", r2.Notes)
	}
}

const pbBundle = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n" +
	"-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"

func TestTLSTrust(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{
		"/etc/ssl/certs/ca-certificates.crt":                    pbBundle,
		"/usr/local/share/ca-certificates/corp-root.crt":        "x",
		"/usr/local/share/ca-certificates/sub/corp-issuing.pem": "y",
		"/opt/jdk/lib/security/cacerts":                         "certs",
	})
	e.PathBins["openssl"] = "/usr/bin/openssl"
	e.Cmds["openssl x509 -noout -subject -enddate -in /usr/local/share/ca-certificates/corp-root.crt"] =
		fakeCmd{Stdout: "subject=CN = Corp Root CA, O = Corp\nnotAfter=Jan  1 00:00:00 2035 GMT\n"}
	e.Vars["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
	e.Vars["GIT_SSL_NO_VERIFY"] = "false"
	e.Vars["SSL_CERT_FILE"] = "/etc/ssl/corp.pem"
	e.Vars["JAVA_HOME"] = "/opt/jdk"
	r := pbRun(e, "tls.trust")
	d := r.Data
	pbKeys(t, d, "bundles", "roots", "enterprise_roots", "custom_anchors", "root_count", "authroot_count",
		"root_auto_update", "default_bundle", "runtime_trust", "java_cacerts")
	b := d.vals["bundles"].([]any)[0].(*Obj)
	pbEq(t, "bundle certs", b.vals["certs"], NumText("2"))
	pbEq(t, "subjects", pbStrs(pbGet(t, d, "enterprise_roots")), []string{"CN = Corp Root CA, O = Corp", "corp-issuing.pem"})
	pbEq(t, "anchors", pbStrs(pbGet(t, d, "custom_anchors")), []string{
		"/usr/local/share/ca-certificates/corp-root.crt", "/usr/local/share/ca-certificates/sub/corp-issuing.pem"})
	root0 := d.vals["roots"].([]any)[0].(*Obj)
	pbEq(t, "not_after", root0.Str("not_after"), "Jan  1 00:00:00 2035 GMT")
	pbEq(t, "default", d.Str("default_bundle"), "/etc/ssl/certs/ca-certificates.crt")
	rt := pbGet(t, d, "runtime_trust").(*Obj)
	pbEq(t, "runtime keys", rt.Keys(), []string{"SSL_CERT_FILE", "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY"})
	pbEq(t, "named", rt.vals["SSL_CERT_FILE"], Named{Name: "SSL_CERT_FILE", Value: "/etc/ssl/corp.pem"})
	jc := pbGet(t, d, "java_cacerts").(*Obj)
	pbEq(t, "cacerts size", jc.vals["size_bytes"], NumText("5"))
	pbEq(t, "facts", []string{r.Facts["ca_custom"], r.Facts["tls_disabled_env"], r.Facts["ca_bundle"]},
		[]string{"2", "NODE_TLS_REJECT_UNAUTHORIZED=0\n", "/etc/ssl/certs/ca-certificates.crt"})
	pbEq(t, "status", r.Status, StOK)
}

func TestTLSTrustDistrolessAndNetworkJavaHome(t *testing.T) {
	e := pbNewEnv(t)
	e.Vars["JAVA_HOME"] = "/net/jdk"
	e.NetPaths = []string{"/net"}
	pbWrite(t, e.Root, map[string]string{"/net/jdk/lib/security/cacerts": "x"})
	r := pbRun(e, "tls.trust")
	pbEq(t, "status", r.Status, StPartial)
	pbEq(t, "java_cacerts", pbGet(t, r.Data, "java_cacerts"), nil)
	if !pbHasNote(r, "no CA bundle found") || !pbHasNote(r, "/net/jdk/lib/security/cacerts") {
		t.Errorf("notes %v", r.Notes)
	}
	pbEq(t, "ca_custom", r.Facts["ca_custom"], "0")
}

func TestLsDate(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pbEq(t, "recent", pbLsDate(time.Date(2026, 5, 3, 7, 8, 0, 0, time.UTC), now), "May 3 07:08")
	pbEq(t, "old", pbLsDate(time.Date(2024, 1, 9, 7, 8, 0, 0, time.UTC), now), "Jan 9 2024")
}

const pbKeytoolOut = "Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains 2 entries\n\n" +
	"Alias name: a\nOwner: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US\n" +
	"Alias name: b\nOwner: CN=ISRG Root X1, O=Internet Security Research Group, C=US\n"

func TestTLSJavaCacerts(t *testing.T) {
	e := pbNewEnv(t)
	e.Vars["JAVA_HOME"] = "/opt/jdk"
	pbWrite(t, e.Root, map[string]string{"/opt/jdk/bin/keytool": "x", "/opt/jdk/lib/security/cacerts": "x"})
	e.FactsIn["ca_subjects"] = "CN = Corp Root CA, O = Corp\nISRG Root X1\ncorp-issuing.pem\n"
	e.Cmds["keytool -list -v -cacerts -storepass changeit"] = fakeCmd{Exit: 1, Stderr: "Illegal option:  -cacerts\n"}
	e.Cmds["keytool -list -v -keystore /opt/jdk/lib/security/cacerts -storepass changeit"] = fakeCmd{Stdout: pbKeytoolOut}
	r := pbRun(e, "tls.java_cacerts")
	pbKeys(t, r.Data, "keytool", "entries", "owners", "enterprise_roots_missing")
	pbEq(t, "entries", pbGet(t, r.Data, "entries"), NumText("2"))
	pbEq(t, "owners", len(pbStrs(pbGet(t, r.Data, "owners"))), 2)
	pbEq(t, "missing", pbStrs(pbGet(t, r.Data, "enterprise_roots_missing")), []string{"Corp Root CA", "corp-issuing.pem"})
	pbEq(t, "fact", r.Facts["java_missing_roots"], "Corp Root CA\ncorp-issuing.pem\n")
}

func TestTLSJavaCacertsStatuses(t *testing.T) {
	none := pbNewEnv(t)
	r := pbRun(none, "tls.java_cacerts")
	pbEq(t, "not found", r.Status, StNotFound)

	shim := pbNewEnv(t)
	shim.PathBins["keytool"] = "/home/u/.sdkman/shims/keytool"
	shim.NoRun["/home/u/.sdkman/shims/keytool"] = "version-manager shim (sdkman, not executed)"
	r = pbRun(shim, "tls.java_cacerts")
	pbEq(t, "skipped", r.Status, StSkipped)
	if len(shim.Ran) != 0 {
		t.Errorf("ran %v", shim.Ran)
	}

	bad := pbNewEnv(t)
	bad.PathBins["keytool"] = "/usr/bin/keytool"
	bad.Cmds["keytool -list -v -cacerts -storepass changeit"] = fakeCmd{Exit: 1, Stderr: "keytool error: x\n"}
	r = pbRun(bad, "tls.java_cacerts")
	pbEq(t, "error", []string{r.Status, r.Error}, []string{StError, "keytool failed (exit 1)"})

	net := pbNewEnv(t)
	net.Vars["JAVA_HOME"] = "/net/jdk"
	net.NetPaths = []string{"/net"}
	r = pbRun(net, "tls.java_cacerts")
	pbEq(t, "network keytool not found", r.Status, StNotFound)
}
