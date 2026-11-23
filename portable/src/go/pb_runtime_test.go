package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionManagers(t *testing.T) {
	e := pbNewEnv(t)
	e.Vars["PATH"] = "/home/u/.pyenv/shims/:/home/u/.cargo/bin:/usr/bin"
	pbMkdir(t, e.Root, "/home/u/.pyenv/shims", "/home/u/.pyenv/versions/3.11.4", "/home/u/.pyenv/versions/3.12.1",
		"/home/u/.asdf/installs/nodejs/20.11.0", "/home/u/.cargo/bin")
	r := pbRun(e, "runtime.version_managers")
	ids := map[string]*Obj{}
	for _, m := range r.Data.vals["managers"].([]any) {
		ids[m.(*Obj).Str("id")] = m.(*Obj)
	}
	py := ids["pyenv"]
	pbEq(t, "pyenv", []any{pbStrs(py.vals["shim_dirs"]), pbStrs(py.vals["versions"])},
		[]any{[]string{"/home/u/.pyenv/shims"}, []string{"3.11.4", "3.12.1"}})
	pbEq(t, "asdf", pbStrs(ids["asdf"].vals["versions"]), []string{"nodejs/20.11.0"})
	if _, ok := ids["rustup"]; ok {
		t.Error("~/.cargo/bin without rustup is no shim directory")
	}
	pbEq(t, "fact", r.Facts["vmanagers"], itoa(len(ids)))
	pbEq(t, "none", pbRun(pbNewEnv(t), "runtime.version_managers").Status, StNotFound)
	pbWrite(t, e.Root, map[string]string{"/home/u/.cargo/bin/rustup": "x"})
	pbEq(t, "rustup shim", pbShimOf(e, "/home/u/.cargo/bin//"), "rustup")
}

func TestTailComponents(t *testing.T) {
	pbEq(t, "2", pbTailComponents("~/.asdf/installs/*/*", "/h/.asdf/installs/node/20/"), "node/20")
	pbEq(t, "1", pbTailComponents("/x/y", "/x/y"), "y")
}

func TestRuntimeJava(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{
		"/opt/jdk17/release":  "JAVA_VERSION=\"17.0.9\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\nOS_ARCH=\"aarch64\"\nJAVA_RUNTIME_VERSION=\"17.0.9+9\"\n",
		"/opt/jdk17/bin/java": "x", "/opt/jdk17/bin/javac": "x",
		"/usr/lib/jvm/jre8/bin/java":  "x",
		"/usr/lib/jvm/notajdk/readme": "x",
		"/home/u/.jdks/local/release": "JAVA_VERSION='21'\n",
		"/net/jdk/release":            "JAVA_VERSION=\"11\"\n",
		"/usr/local/stub/java":        "x",
	})
	e.Vars["JAVA_HOME"] = "/net/jdk"
	e.NetPaths = []string{"/net"}
	e.PathBins["java"] = "/usr/local/stub/java"
	e.Cmds["java -XshowSettings:properties -version"] = fakeCmd{Stderr: "Property settings:\n    java.home = /opt/jdk17\n    java.version = 17\n"}
	r := pbRun(e, "runtime.java")
	pbKeys(t, r.Data, "java_home", "jdks")
	got := []string{}
	for _, j := range r.Data.vals["jdks"].([]any) {
		o := j.(*Obj)
		got = append(got, o.Str("path")+"|"+o.Str("version")+"|"+o.Str("kind")+"|"+o.Str("source")+"|"+o.Str("arch"))
	}
	pbEq(t, "jdks", got, []string{"/opt/jdk17|17.0.9|jdk|PATH|arm64", "/usr/lib/jvm/jre8||jre|directory|", "/home/u/.jdks/local|21|jre|directory|"})
	pbEq(t, "facts", []string{r.Facts["jdk_count"], r.Facts["java_versions"]}, []string{"3", "17.0.9 (jdk)\nunknown (jre)\n21 (jre)\n"})
	if !pbHasNote(r, "/net/jdk") {
		t.Errorf("notes %v", r.Notes)
	}
	pbEq(t, "none", pbRun(pbNewEnv(t), "runtime.java").Status, StNotFound)
}

func TestRuntimeDotnet(t *testing.T) {
	e := pbNewEnv(t)
	e.PathBins["dotnet"] = "/usr/bin/dotnet"
	e.Cmds["dotnet --list-sdks"] = fakeCmd{Stdout: "8.0.100 [/usr/share/dotnet/sdk]\n6.0.400 [/usr/share/dotnet/sdk]\n"}
	e.Cmds["dotnet --list-runtimes"] = fakeCmd{Stdout: "Microsoft.NETCore.App 8.0.0 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\n"}
	r := pbRun(e, "runtime.dotnet")
	pbKeys(t, r.Data, "framework", "dotnet", "sdks", "runtimes")
	pbEq(t, "sdks", pbStrs(r.Data.vals["sdks"]), []string{"8.0.100", "6.0.400"})
	pbEq(t, "runtimes", pbStrs(r.Data.vals["runtimes"]), []string{"Microsoft.NETCore.App 8.0.0"})
	pbEq(t, "fact", r.Facts["dotnet_sdks"], "8.0.100\n6.0.400")

	s := pbNewEnv(t)
	s.Vars["DOTNET_ROOT"] = "/home/u/.dotnet-shim"
	pbWrite(t, s.Root, map[string]string{"/home/u/.dotnet-shim/dotnet": "x"})
	pbMkdir(t, s.Root, "/home/u/.dotnet-shim/sdk/7.0.1", "/home/u/.dotnet-shim/shared/Microsoft.NETCore.App/7.0.2")
	s.NoRun["/home/u/.dotnet-shim/dotnet"] = "in a world-writable directory without the sticky bit (not executed)"
	r = pbRun(s, "runtime.dotnet")
	pbEq(t, "dir sdks", pbStrs(r.Data.vals["sdks"]), []string{"7.0.1"})
	pbEq(t, "dir runtimes", pbStrs(r.Data.vals["runtimes"]), []string{"Microsoft.NETCore.App 7.0.2"})
	if len(s.Ran) != 0 || !pbHasNote(r, "versions read from the install directory") {
		t.Errorf("ran %v notes %v", s.Ran, r.Notes)
	}

	n := pbNewEnv(t)
	n.Vars["DOTNET_ROOT"] = "/net/dotnet"
	n.NetPaths = []string{"/net"}
	r = pbRun(n, "runtime.dotnet")
	pbKeys(t, r.Data, "framework", "sdks", "runtimes")
	pbEq(t, "not found", r.Status, StNotFound)
}

func TestRuntimePython(t *testing.T) {
	e := pbNewEnv(t)
	e.Vars["PATH"] = "/home/u/.pyenv/shims:/usr/bin:/mnt/c/Users/u/AppData/Local/Microsoft/WindowsApps"
	pbWrite(t, e.Root, map[string]string{"/home/u/.pyenv/shims/python": "x", "/usr/bin/python3": "x", "/usr/bin/python3.11": "x",
		"/mnt/c/Users/u/AppData/Local/Microsoft/WindowsApps/python3": "x"})
	e.NoRun["/home/u/.pyenv/shims/python"] = "version-manager shim (pyenv, not executed)"
	e.NoRun["/mnt/c/Users/u/AppData/Local/Microsoft/WindowsApps/python3"] = "Windows app execution alias (not executed)"
	e.Cmds["python3 --version"] = fakeCmd{Stdout: "Python 3.11.4\n"}
	e.Cmds["python3.11 --version"] = fakeCmd{Stdout: "Python 3.11.4\n"}
	r := pbRun(e, "runtime.python")
	pbKeys(t, r.Data, "interpreters", "launcher")
	got := []string{}
	for _, i := range r.Data.vals["interpreters"].([]any) {
		o := i.(*Obj)
		got = append(got, o.Str("path")+"|"+o.Str("version")+"|"+pbBool(o.vals["store_alias"].(bool))+"|"+o.Str("not_run_reason"))
	}
	pbEq(t, "interpreters", got, []string{"/usr/bin/python3|3.11.4|false|",
		"/mnt/c/Users/u/AppData/Local/Microsoft/WindowsApps/python3||true|Windows app execution alias (not executed)",
		"/home/u/.pyenv/shims/python||false|version-manager shim (pyenv, not executed)",
		"/usr/bin/python3.11|3.11.4|false|"})
	pbEq(t, "facts", []string{r.Facts["python_found"], r.Facts["python_versions"]},
		[]string{"true", "3.11.4\nunknown (not run)\nunknown (not run)\n3.11.4\n"})
	if pbRan(e, "shims") || pbRan(e, "WindowsApps") {
		t.Errorf("ran %v", e.Ran)
	}
	r = pbRun(pbNewEnv(t), "runtime.python")
	pbEq(t, "none", []string{r.Status, r.Facts["python_found"]}, []string{StNotFound, "false"})
}

func TestNativeDepsGlibc(t *testing.T) {
	e := pbNewEnv(t)
	cxx := "\x7fELF\x00GLIBCXX_3.4\x00GLIBCXX_3.4.9\x00GLIBCXX_3.4.30\x00GLIBCXX_DEBUG_MESSAGE_LENGTH\x00GLIBCXX_3.4.4\x00"
	pbWrite(t, e.Root, map[string]string{"/usr/lib/x86_64-linux-gnu/libstdc++.so.6": cxx,
		"/etc/odbcinst.ini": "[ODBC]\nTrace=No\n[PostgreSQL Unicode]\nDriver=x\n[FreeTDS]\n"})
	e.PathBins["getconf"] = "/usr/bin/getconf"
	e.PathBins["ldconfig"] = "/sbin/ldconfig"
	e.PathBins["fc-list"] = "/usr/bin/fc-list"
	e.Cmds["getconf GNU_LIBC_VERSION"] = fakeCmd{Stdout: "glibc 2.35\n"}
	e.Cmds["ldconfig -p"] = fakeCmd{Stdout: "1234 libs found in cache `/etc/ld.so.cache'\n" +
		"\tlibstdc++.so.6 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libstdc++.so.6\n" +
		"\tlibssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3\n\tlibssl.so.1.1 (libc6,x86-64) => /x\n"}
	e.Cmds["fc-list"] = fakeCmd{Stdout: "a\nb\nc\n"}
	re := &pbRecEnv{fakeEnv: e}
	r := pbRun(re, "native.deps")
	pbKeys(t, r.Data, "libc", "glibcxx_max", "libstdcxx_path", "libssl", "vcredist", "ucrt", "webview2", "odbc_drivers", "fonts_count")
	pbEq(t, "libc", []string{r.Data.vals["libc"].(*Obj).Str("kind"), r.Data.vals["libc"].(*Obj).Str("version")}, []string{"glibc", "2.35"})
	pbEq(t, "glibcxx", r.Data.Str("glibcxx_max"), "3.4.30")
	pbEq(t, "libssl", pbStrs(r.Data.vals["libssl"]), []string{"libssl.so.1.1", "libssl.so.3"})
	pbEq(t, "odbc", pbStrs(r.Data.vals["odbc_drivers"]), []string{"PostgreSQL Unicode", "FreeTDS"})
	pbEq(t, "fonts", r.Data.vals["fonts_count"], NumText("3"))
	pbEq(t, "fc env", re.opts[len(re.opts)-1].Env, []string{"XDG_CACHE_HOME=" + e.TempDir() + "/fc-cache"})
	pbEq(t, "status", r.Status, StOK)
	pbEq(t, "facts", []string{r.Facts["libc_kind"], r.Facts["glibcxx_max"]}, []string{"glibc", "3.4.30"})
}

func TestNativeDepsMuslAndDistroless(t *testing.T) {
	e := pbNewEnv(t)
	pbWrite(t, e.Root, map[string]string{"/lib/ld-musl-x86_64.so.1": "x", "/usr/lib/libssl.so.3": "x", "/usr/lib/libstdc++.so.6": "GLIBCXX_3.4.29"})
	e.PathBins["ldd"] = "/usr/bin/ldd"
	e.Cmds["ldd --version"] = fakeCmd{Exit: 1, Stderr: "musl libc (x86_64)\nVersion 1.2.4\nDynamic Program Loader\n"}
	r := pbRun(e, "native.deps")
	pbEq(t, "musl", r.Data.vals["libc"].(*Obj).Str("version"), "1.2.4")
	pbEq(t, "libssl", pbStrs(r.Data.vals["libssl"]), []string{"libssl.so.3"})
	pbEq(t, "cxx", []string{r.Data.Str("libstdcxx_path"), r.Data.Str("glibcxx_max")}, []string{"/usr/lib/libstdc++.so.6", "3.4.29"})

	d := pbNewEnv(t)
	r = pbRun(d, "native.deps")
	pbEq(t, "distroless", []any{r.Status, r.Notes, r.Data.vals["fonts_count"]}, []any{StPartial, []string{"C library could not be identified"}, nil})

	g := pbNewEnv(t)
	g.PathBins["ldd"] = "/usr/bin/ldd"
	g.Cmds["ldd --version"] = fakeCmd{Stdout: "ldd (GNU libc) 2.17\nCopyright\n"}
	r = pbRun(g, "native.deps")
	pbEq(t, "ldd glibc", r.Data.vals["libc"].(*Obj).Str("version"), "2.17")
}

func TestUtilHelpers(t *testing.T) {
	pbEq(t, "exec", pbIsExec(FileInfo{Type: TypeFile, Mode: 0o755}), true)
	pbEq(t, "unquote", []string{pbUnquote(` "a b" `), pbUnquote("'x'"), pbUnquote(`"`)}, []string{"a b", "x", `"`})
	pbEq(t, "versionOf", []string{pbVersionOf("Python 3.11.4"), pbVersionOf("v20"), pbVersionOf("none")}, []string{"3.11.4", "20", ""})
	pbEq(t, "normdir", pbNormDir("/a//b///"), "/a/b")
	pbEq(t, "dir", []string{pbDir("/a/b"), pbDir("/a"), pbDir("a")}, []string{"/a", "/", "/"})
	sk := &pbSkips{}
	for _, p := range []string{"/n1", "/n2", "/n3", "/n4", "/n5", "/n6", "/n6"} {
		sk.addNet(p)
	}
	sk.addCred("/home/u/.m2/repository")
	r := newResult("x")
	sk.note(r)
	pbEq(t, "notes", r.Notes, []string{"/home/u/.m2/repository not read: link to a credential store",
		"not read because they are on network or autofs mounts (nothing there is touched): /n1, /n2, /n3, /n4, /n5 and 1 more"})
}

func TestResolveLinks(t *testing.T) {
	e := pbNewEnv(t)
	pbMkdir(t, e.Root, "/opt/jdk-17/bin", "/usr/bin")
	if err := os.Symlink("../../opt/jdk-17/bin/java", filepath.Join(e.Root, "usr", "bin", "java")); err != nil {
		t.Skip("symbolic links not available: " + err.Error())
	}
	pbEq(t, "realpath", pbRealpath(e, "/usr/bin/./java"), "/opt/jdk-17/bin/java")
	e.NetPaths = []string{"/opt"}
	rp, ok, why := pbResolve(e, "/usr/bin/java")
	if ok || !strings.Contains(why, "network") || rp != "/opt/jdk-17/bin/java" {
		t.Errorf("resolve %q %v %q", rp, ok, why)
	}
}
