package main

import "testing"

func TestCredPath(t *testing.T) {
	stores := []string{"/home/u/.ssh", "/home/u/.ssh/config", "/home/u/.SSH/x", "/home/u/.config/gcloud/a",
		"/home/u/.config//gcloud/x", "/home/u/.config/./gcloud/x", "/home/u/.netrc", "/home/u/_NETRC",
		"/home/u/.docker/config.json", "/home/u/.bash_history", "/home/u/x/id_rsa", "/home/u/id_rsa/",
		"/home/u/.ssh./id", "/home/u/.ssh /id", "/home/u/k.PEM", "/etc/ssl/private/server.key",
		"/var/run/secrets/kubernetes.io/serviceaccount/token", "/x/.pypirc", "/home/u/a/../.aws/creds",
		"/etc/ssl/certs/my-key.pem", "/home/u/cacerts.p12"}
	for _, p := range stores {
		if !credPath(p) {
			t.Errorf("%s should be a credential store", p)
		}
	}
	free := []string{"/etc/os-release", "/home/u/.config/pip/pip.conf", "/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/foo.pem", "/usr/local/share/ca-certificates/corp.pem", "/etc/ssl/cert.pem",
		"/usr/lib/jvm/x/lib/security/cacerts", "/home/u/.sshx/a", "/home/u/.config/gh/config.yml", "/x/history"}
	for _, p := range free {
		if credPath(p) {
			t.Errorf("%s should not be a credential store", p)
		}
	}
}

func TestCredNorm(t *testing.T) {
	cases := map[string]string{"/a//b/./c/": "/a/b/c", "/../a": "/a", "a/../../b": "../b", "./": ".", "/a/b/..": "/a"}
	for in, want := range cases {
		if got := credNorm(in); got != want {
			t.Errorf("credNorm(%q)=%q want %q", in, got, want)
		}
	}
}
