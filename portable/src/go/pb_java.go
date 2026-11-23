// pb_java.go: runtime.java (port of src/sh/25-tools.sh probe_runtime_java, Linux branches).
package main

import (
	"strings"
)

func init() {
	registerProbe("runtime.java", probeRuntimeJava)
}

// pbJDKPatterns: the known JDK directories (sh probe_runtime_java's generic list).
var pbJDKPatterns = []string{"/usr/lib/jvm/*", "/usr/java/*", "/opt/*jdk*", "/opt/java/*",
	"/Library/Java/JavaVirtualMachines/*/Contents/Home", "~/Library/Java/JavaVirtualMachines/*/Contents/Home",
	"~/.sdkman/candidates/java/*", "~/.jdks/*"}

type pbJDKs struct {
	e     Env
	sk    *pbSkips
	homes [][2]string // home, source
	real  map[string]bool
}

// add is sh es_jdk_add: a Java home (bin/java or release in it), once per real path.
func (j *pbJDKs) add(home, source string) {
	if !pbLocal(j.e, j.sk, home) || !pbIsDir(j.e, home) {
		return
	}
	if !(pbLocal(j.e, j.sk, home+"/bin/java") && pbExecFile(j.e, home+"/bin/java")) &&
		!(pbLocal(j.e, j.sk, home+"/release") && pbIsFile(j.e, home+"/release")) {
		return
	}
	rp := pbRealpath(j.e, home)
	if j.real[rp] {
		return
	}
	j.real[rp] = true
	j.homes = append(j.homes, [2]string{home, source})
}

// fromPath adds the Java home of the java on PATH (from its real path, or from the JVM's own
// java.home when the PATH java is a launcher stub).
func (j *pbJDKs) fromPath(r *Result) {
	jw, ok := j.e.Which("java")
	if !ok {
		return
	}
	if run, _ := j.e.Runnable(jw); !run {
		return
	}
	rp := pbRealpath(j.e, jw)
	jp := strings.TrimSuffix(strings.TrimSuffix(rp, "/bin/java"), "/jre")
	if jp != rp && (pbIsFile(j.e, jp+"/release") || pbIsDir(j.e, jp+"/lib")) {
		j.add(jp, "PATH")
		return
	}
	c := runPath(j.e, r, RunOpt{MergeStderr: true}, jw, "-XshowSettings:properties", "-version")
	if c.Exit != 0 {
		return
	}
	for _, l := range lines(c.Stdout) {
		t := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(t, "java.home = ") {
			if h := strings.TrimSuffix(strings.TrimPrefix(t, "java.home = "), "/jre"); h != "" {
				j.add(h, "PATH")
			}
			return
		}
	}
}

// pbJavaRelease reads JAVA_VERSION, IMPLEMENTOR, OS_ARCH and JAVA_RUNTIME_VERSION of <jdk>/release.
func pbJavaRelease(e Env, home string) map[string]string {
	out := map[string]string{}
	if !pbLocal(e, nil, home+"/release") {
		return out
	}
	text, _, err := e.ReadText(home+"/release", 1<<20)
	if err != nil {
		return out
	}
	for _, l := range lines(text) {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			switch k {
			case "JAVA_VERSION", "IMPLEMENTOR", "OS_ARCH", "JAVA_RUNTIME_VERSION":
				out[k] = pbUnquote(v)
			}
		}
	}
	return out
}

func probeRuntimeJava(e Env, r *Result) {
	j := &pbJDKs{e: e, sk: &pbSkips{}, real: map[string]bool{}}
	jh, _ := e.Getenv("JAVA_HOME")
	if jh != "" {
		j.add(jh, "JAVA_HOME")
	}
	j.fromPath(r)
	r.Src("read <jdk>/release for JAVA_HOME, PATH java and the known JDK directories")
	for _, pat := range pbJDKPatterns {
		for _, d := range pbExpand(e, j.sk, pat) {
			if pbIsDir(e, d) {
				j.add(d, "directory")
			}
		}
	}
	r.Data.Set("java_home", strOrNil(jh))
	items, vers := []any{}, []string{}
	for _, h := range j.homes {
		rel := pbJavaRelease(e, h[0])
		kind := "jre"
		if pbLocal(e, nil, h[0]+"/bin/javac") && pbExecFile(e, h[0]+"/bin/javac") {
			kind = "jdk"
		}
		arch := rel["OS_ARCH"]
		if arch != "" {
			arch = pbNormArch(arch)
		}
		items = append(items, NewObj().Set("path", h[0]).Set("version", strOrNil(rel["JAVA_VERSION"])).
			Set("runtime_version", strOrNil(rel["JAVA_RUNTIME_VERSION"])).Set("vendor", strOrNil(rel["IMPLEMENTOR"])).
			Set("arch", strOrNil(arch)).Set("kind", kind).Set("source", h[1]))
		v := rel["JAVA_VERSION"]
		if v == "" {
			v = "unknown"
		}
		vers = append(vers, v+" ("+kind+")")
	}
	r.Data.Set("jdks", items)
	j.sk.note(r)
	if len(items) == 0 {
		r.SetStatus(StNotFound, "")
	}
	r.Fact("jdk_count", itoa(len(items)))
	r.Fact("java_versions", pbLines(vers))
}
