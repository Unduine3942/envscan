// redact_edge_test.go: edge cases from the comments of redact.awk (private keys, URL userinfo,
// JSON/XML/YAML forms, command-line options, tokens by prefix and minimum length, UTF-8). The
// expected values are the output of the reference redact.awk (gawk --posix, LC_ALL=C), except
// text_crlf: a "\r" before "\n" is dropped (sh read_file), where the awk test harness keeps it.
package main

import (
	"strings"
	"testing"
)

var redactEdgeCases = []struct {
	name, op string
	args     []string
	want     string
}{
	{"pk_rsa", "value", []string{"-----BEGIN RSA PRIVATE KEY-----\nMIIEow"}, "<redacted: private key>"},
	{"pk_text", "text", []string{"a: 1\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\n"}, "<redacted: private key>"},
	{"url_userinfo", "value", []string{"git clone https://bob:S3cr3t@git.corp/x.git now"}, "git clone https://bob:<redacted>@git.corp/x.git now"},
	{"url_at_password", "value", []string{"https://u:a@b@c@host.corp:8443/p?q=1"}, "https://u:<redacted>@host.corp:8443/p?q=1"},
	{"url_long_token_user", "value", []string{"https://abcdefghijklmnopqrstuvwxyz@h.corp/"}, "https://<redacted>@h.corp/"},
	{"url_short_user", "value", []string{"ssh://git@h.corp/r"}, "ssh://git@h.corp/r"},
	{"conda", "value", []string{"https://c.corp/t/abcdefgh12/x/t/zz/"}, "https://c.corp/t/<redacted>/x/t/zz/"},
	{"bare_ui_list", "value", []string{"http=u:a@p1:80;https=u:b@p2:81"}, "http=u:<redacted>@p1:80;https=u:<redacted>@p2:81"},
	{"bare_ui_sentence", "value", []string{"via bob:pw@proxy.corp:8080."}, "via bob:<redacted>@proxy.corp:8080."},
	{"bare_ui_git", "value", []string{"git@github.com:org/repo.git"}, "git@github.com:org/repo.git"},
	{"bare_ui_digest", "value", []string{"image:tag@sha256:abcdef0123"}, "image:tag@sha256:abcdef0123"},
	{"bare_ui_ipv6", "value", []string{"u:pw@[fe80::1]:3128"}, "u:<redacted>@[fe80::1]:3128"},
	{"json_pw", "value", []string{"{\"password\":\"x y\",\"user\":\"u\"}"}, "{\"password\":\"<redacted>\",\"user\":\"u\"}"},
	{"json_escaped", "value", []string{"{\\\"token\\\":\\\"abc\\\"}"}, "{\\\"token\\\":\\\"<redacted>\\\"}"},
	{"json_nested", "value", []string{"{\"secret\": {\"a\": 1}}"}, "{\"secret\": <redacted>"},
	{"xml_el", "line", []string{"  <password>abc</password>"}, "  <password><redacted></password>"},
	{"xml_attr", "line", []string{"<server password=\"pw\" user=\"u\"/>"}, "<server password=<redacted> user=\"u\"/>"},
	{"xml_nuget", "line", []string{"<add key=\"ClearTextPassword\" value=\"pw\" />"}, "<add key=\"ClearTextPassword\" value=\"<redacted>\" />"},
	{"xml_nuget_apikey", "line", []string{"<add key=\"https://nuget.corp/v3/index.json\" value=\"oy2abc\" />"}, "<add key=\"https://nuget.corp/v3/index.json\" value=\"<redacted>\" />"},
	{"yaml_line", "line", []string{"  - token: \"abc\""}, "  - token: <redacted>"},
	{"export_line", "line", []string{"export GITHUB_TOKEN=ghp_xxx"}, "export GITHUB_TOKEN=<redacted>"},
	{"set_line", "line", []string{"set DB_PASSWORD=hunter2"}, "set DB_PASSWORD=<redacted>"},
	{"space_pair", "line", []string{"password \"x y\" other"}, "password \"<redacted>\" other"},
	{"yarn_classic", "line", []string{"\"//reg.corp/:_authToken\" \"abc\""}, "\"//reg.corp/:_authToken\" \"<redacted>\""},
	{"token_prefix", "value", []string{"x ghp_0123456789abcdefghijABCDEFGHIJ0123 y"}, "x <redacted> y"},
	{"token_after_word", "value", []string{"xghp_0123456789abcdefghijABCDEFGHIJ0123"}, "xghp_0123456789abcdefghijABCDEFGHIJ0123"},
	{"token_akia_20", "value", []string{"AKIA0123456789ABCDEF"}, "<redacted>"},
	{"token_akia_19", "value", []string{"AKIA0123456789ABCDE"}, "AKIA0123456789ABCDE"},
	{"token_jwt", "value", []string{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}, "jwt <redacted>"},
	{"bearer", "value", []string{"Authorization: Bearer abcdefgh12345=="}, "Authorization: Bearer <redacted>"},
	{"bearer_short", "value", []string{"Bearer abc"}, "Bearer abc"},
	{"basic", "value", []string{"basic dXNlcjpwYXNz"}, "basic <redacted>"},
	{"authz_json", "value", []string{"{\"Proxy-Authorization\": \"Basic dXNlcjpwYXNz\"}"}, "{\"Proxy-Authorization\": \"Basic <redacted>\"}"},
	{"pairkey_conn", "value", []string{"Server=db;Database=x;User Id=u;Password=p@ss;Encrypt=true"}, "Server=db;Database=x;User Id=u;Password=<redacted>;Encrypt=true"},
	{"pairkey_quoted", "value", []string{"Pwd='a;b';Server=x"}, "Pwd=<redacted>;Server=x"},
	{"run_sep", "value", []string{"password=a;b c"}, "password=<redacted> c"},
	{"run_key_follows", "value", []string{"Pwd=a;Database=x"}, "Pwd=<redacted>;Database=x"},
	{"placeholder_twice", "value", []string{"Pwd=<redacted>rest"}, "Pwd=<redacted>"},
	{"cmd_user", "cmd", []string{"curl -u bob:secret https://x"}, "curl -u bob:<redacted> https://x"},
	{"cmd_user_attached", "cmd", []string{"curl -ubob:secret https://x"}, "curl -ubob:<redacted> https://x"},
	{"cmd_proxy_user", "cmd", []string{"curl --proxy-user 'bob:pa ss' x"}, "curl --proxy-user 'bob:<redacted>' x"},
	{"cmd_mysql", "cmd", []string{"mysql -psecret -h db -P 3306"}, "mysql -p<redacted> -h db -P 3306"},
	{"cmd_mysql_exe", "cmd", []string{"C:\\bin\\mysql.exe -p secret"}, "C:\\bin\\mysql.exe -p <redacted>"},
	{"cmd_schtasks", "cmd", []string{"schtasks /Create /rp s3cret /TN x"}, "schtasks /Create /rp <redacted> /TN x"},
	{"cmd_7z", "cmd", []string{"7z a -pSecretPw out.7z"}, "7z a -p<redacted> out.7z"},
	{"cmd_header", "cmd", []string{"curl -H \"X-Api-Key: abc123\" -H 'Accept: x' u"}, "curl -H \"X-Api-Key: <redacted>\" -H 'Accept: x' u"},
	{"cmd_option_eq", "cmd", []string{"java -Dhttp.proxyPassword=hunter2 -Xmx1g"}, "java -Dhttp.proxyPassword=<redacted> -Xmx1g"},
	{"cmd_option_space", "cmd", []string{"app --api-key \"a b\" --verbose"}, "app --api-key <redacted> --verbose"},
	{"cmd_option_escaped", "cmd", []string{"app --token \\\"abc def\\\" x"}, "app --token \\\"<redacted>\\\" x"},
	{"cmd_slash_option", "cmd", []string{"tool /password:xyz /quiet"}, "tool /password:<redacted> /quiet"},
	{"named_secret", "named", []string{"NPM_TOKEN", "abc"}, "<redacted>"},
	{"named_plain", "named", []string{"JAVA_OPTS", "-Djavax.net.ssl.keyStorePassword=changeit"}, "-Djavax.net.ssl.keyStorePassword=<redacted>"},
	{"utf8_key", "value", []string{"\xe5\xaf\x86\xe7\xa0\x81 password=\xe7\xa7\x98\xe5\xaf\x86\xe5\x80\xbc next"}, "\xe5\xaf\x86\xe7\xa0\x81 password=<redacted> next"},
	{"utf8_line", "line", []string{"\xc3\xa4\xc3\xb6: token=\xc3\xbc\xc3\xbc\xc3\xbc"}, "\xc3\xa4\xc3\xb6: token=<redacted>"},
	{"invalid_utf8", "value", []string{"password=\xff\xfe x \xc3"}, "password=<redacted> x \xc3"},
	{"invalid_utf8_line", "line", []string{"\xffsecret: \xfe\xfd"}, "\xffsecret: <redacted>"},
	{"text_json_block", "text", []string{"{\n  \"auths\": {\n    \"reg\": {\"auth\": \"dXNlcjpwYXNz\"}\n  },\n  \"x\": 1\n}"}, "{\n  \"auths\": {\n    \"reg\": {\"auth\": \"<redacted>\"}\n  },\n  \"x\": 1\n}"},
	{"text_yaml_block", "text", []string{"credentials:\n  user: bob\n  pass: x\nnext: 1\n"}, "credentials:\n  <redacted>\n  <redacted>\nnext: 1\n"},
	{"text_yaml_scalar", "text", []string{"key: |\n  line1\n  line2\nother: 1"}, "key: |\n  line1\n  line2\nother: 1"},
	{"text_toml_triple", "text", []string{"token = '''\nabc\n'''\nname = 1"}, "token = <redacted>\n<redacted>\n'''\nname = 1"},
	{"text_xml_open", "text", []string{"<clientSecret>\n  abc\n</clientSecret>\n<x>1</x>"}, "<clientSecret>\n  <redacted>\n</clientSecret>\n<x>1</x>"},
	{"text_dash_items", "text", []string{"secrets:\n- a\n- b\nname: c"}, "secrets:\n<redacted>\n<redacted>\nname: c"},
	{"text_crlf", "text", []string{"password=a\r\nuser=b\r\n"}, "password=<redacted>\nuser=b\n"},
}

func TestRedactEdgeCases(t *testing.T) {
	for _, c := range redactEdgeCases {
		if got := applyRedactionOp(t, c.op, c.args); got != c.want {
			t.Errorf("%s: %s %q:\n got  %q\n want %q", c.name, c.op, c.args, got, c.want)
		}
	}
}

// A second pass changes nothing (the placeholder holds no ":" and counts as one value character).
func TestRedactEdgeCasesStable(t *testing.T) {
	for _, c := range redactEdgeCases {
		if c.op == "named" || c.op == "text" {
			continue
		}
		once := applyRedactionOp(t, c.op, c.args)
		if twice := applyRedactionOp(t, c.op, []string{once.(string)}); twice != once {
			t.Errorf("%s: second pass %q -> %q", c.name, once, twice)
		}
	}
}

func TestRedactLengthCap(t *testing.T) {
	long := strings.Repeat("a", redactMaxLen+1)
	for _, f := range []func(string) string{redactValue, redactLine, redactCmd} {
		if got := f(long); got != redactTooLong {
			t.Errorf("over the cap: %.40q", got)
		}
		if got := f(long[1:]); got != long[1:] {
			t.Errorf("at the cap: changed")
		}
	}
	if got := redactNamed("PATH", long); got != redactTooLong {
		t.Errorf("named over the cap: %.40q", got)
	}
	if got := redactNamed("TOKEN", long); got != "<redacted>" {
		t.Errorf("secret named over the cap: %.40q", got)
	}
}

func TestRedactEmptyAndPlain(t *testing.T) {
	for _, f := range []func(string) string{redactValue, redactLine, redactCmd, redactText} {
		if f("") != "" {
			t.Error("empty input changed")
		}
		if got := f("plain text 123"); got != "plain text 123" {
			t.Errorf("plain text changed: %q", got)
		}
	}
	if redactNamed("TOKEN", "") != "" {
		t.Error("empty secret value changed")
	}
	if isSecretName("") {
		t.Error("empty name is secret")
	}
}

func TestRedactTextKeepsLineStructure(t *testing.T) {
	cases := map[string]string{
		"a\n":               "a\n",
		"a\n\nb":            "a\n\nb",
		"\n":                "\n",
		"token: x\nb\r":     "token: <redacted>\nb\r",
		"x\r\n\r\ny: 1\r\n": "x\n\ny: 1\n",
	}
	for in, want := range cases {
		if got := redactText(in); got != want {
			t.Errorf("redactText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactRulesFromSpec(t *testing.T) {
	if rr.ph != "<redacted>" || rr.minLen != 20 || rr.pkMarker != "PRIVATE KEY" {
		t.Fatalf("spec values: %q %d %q", rr.ph, rr.minLen, rr.pkMarker)
	}
	if got := rr.toolOpts["schtasks"]; strings.Join(got, " ") != "/RP /P" {
		t.Errorf("schtasks options %q", got)
	}
	for _, name := range []string{"mysql", "7z", "ssh-keygen"} {
		if len(rr.toolOpts[name]) == 0 {
			t.Errorf("tool %s missing", name)
		}
	}
}

func TestRedactSpecPanicsOnBrokenTable(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic for a broken redaction table")
		}
	}()
	newRedactRules(map[string]any{"name_segments": "PASSWORD"})
}
