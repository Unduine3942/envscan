// api_netfs.go: the one network file system rule of spec/policy.toml, used by every "network
// mount" decision (mount points of the resolver, PATH search, statfs, fs.mounts, fs.locations,
// env.home, hw.storage).
package main

import (
	"slices"
	"strings"
)

// extraNetFS: es_net_fs_extend of envscan.sh (z/OS and IBM i types spec/policy.toml does not list).
var extraNetFS = []string{"nfs3", "qntc", "qfilesvr.400", "qfilesvr", "automnt", "dfs"}

// isNetworkFSType: the lower-cased mount type t is in network_fs (or es_net_fs_extend), or it
// starts with a network_fs_prefixes entry and is not in local_fuse.
func isNetworkFSType(t string) bool {
	if t == "" {
		return false
	}
	t = strings.ToLower(t)
	if slices.Contains(spec.NetworkFS, t) || slices.Contains(extraNetFS, t) {
		return true
	}
	for _, p := range spec.NetworkFSPrefixes {
		if p != "" && strings.HasPrefix(t, p) {
			return !slices.Contains(spec.LocalFuse, t)
		}
	}
	return false
}
