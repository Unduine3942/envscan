// api_spec.go: the spec tables (spec/*.toml, Unix rows only), embedded at build time as
// spec.json by tools/target_go.py stage (owner: main).
package main

import (
	_ "embed"
	"encoding/json"
)

//go:embed spec.json
var specJSON []byte

type SpecProbe struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Tier      string   `json:"tier"`
	Scope     string   `json:"scope"`
	Footprint []string `json:"footprint"`
}

type SpecTool struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Cat  string   `json:"cat"`
	Mode string   `json:"mode"`
	OS   string   `json:"os"`
	Exe  []string `json:"exe"`
	Args []string `json:"args"`
	Dirs []string `json:"dirs"`
}

type SpecVManager struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Markers  []string `json:"markers"`
	Requires string   `json:"requires"`
	Versions []string `json:"versions"`
}

type SpecConfig struct {
	ID       string   `json:"id"`
	Tool     string   `json:"tool"`
	OS       string   `json:"os"`
	Scope    string   `json:"scope"`
	Mode     string   `json:"mode"`
	MaxBytes int      `json:"max_bytes"`
	Match    []string `json:"match"`
	Paths    []string `json:"paths"`
}

type SpecCache struct {
	ID    string   `json:"id"`
	Tool  string   `json:"tool"`
	Paths []string `json:"paths"`
}

type SpecFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Recommendation string `json:"recommendation"`
}

type SpecDoc struct {
	Name                 string              `json:"name"`
	Version              string              `json:"version"`
	Schema               string              `json:"schema"`
	Probes               []SpecProbe         `json:"probes"`
	Tools                []SpecTool          `json:"tools"`
	VManagers            []SpecVManager      `json:"vmanagers"`
	Configs              []SpecConfig        `json:"configs"`
	Caches               []SpecCache         `json:"caches"`
	Findings             []SpecFinding       `json:"findings"`
	PackageEnv           []string            `json:"package_env"`
	ProxyEnv             []string            `json:"proxy_env"`
	TLSEnv               []string            `json:"tls_env"`
	CABundles            []string            `json:"ca_bundles"`
	CAAnchorDirs         []string            `json:"ca_anchor_dirs"`
	NetworkFS            []string            `json:"network_fs"`
	NetworkFSPrefixes    []string            `json:"network_fs_prefixes"` // fuse.: network unless in LocalFuse
	LocalFuse            []string            `json:"local_fuse"`
	PublicHosts          []string            `json:"public_hosts"`
	NetNever             []string            `json:"net_never"`
	TrustStoreNames      []string            `json:"trust_store_names"`
	Credentials          map[string][]string `json:"credentials"` // folders, files, suffixes, key_extensions
	Redaction            map[string]any      `json:"redaction"`   // spec/redaction.toml as is
	Thresholds           map[string]any      `json:"thresholds"`  // spec/findings.toml [thresholds]
	ChildEnv             map[string]string   `json:"child_env"`
	ChildEnvKeepNames    []string            `json:"child_env_keep_names"`    // the only user variables a child sees
	ChildEnvKeepPrefixes []string            `json:"child_env_keep_prefixes"` // ... or whose name starts with one
	ChildEnvHomePaths    []string            `json:"child_env_home_paths"`    // kept homes: refused -> empty folder
	ChildEnvPathLists    []string            `json:"child_env_path_lists"`    // kept ":" lists: refused entries dropped
}

// spec is loaded once at start; a broken embedded spec is a build bug.
var spec = mustLoadSpec(specJSON)

func mustLoadSpec(b []byte) *SpecDoc {
	var d SpecDoc
	if err := json.Unmarshal(b, &d); err != nil {
		panic("embedded spec.json: " + err.Error())
	}
	return &d
}

func specProbe(id string) (SpecProbe, bool) {
	for _, p := range spec.Probes {
		if p.ID == id {
			return p, true
		}
	}
	return SpecProbe{}, false
}
