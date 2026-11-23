package main

import "testing"

// The network file system rule of spec/policy.toml, shared by every "network mount" decision.
func TestNetworkFSRule(t *testing.T) {
	cases := map[string]bool{
		"fuse.sshfs": true, "fuse.blobfuse2": true, "fuse.unknownthing": true, "fuse": true, "beegfs": true,
		"nfs": true, "NFS4": true, "Fuse.Rclone": true, "nfs3": true, "qntc": true, "dfs": true,
		"fuse.": true, "fuse.bindfs": true, "fuse.mergerfs": true, "fuse.gocryptfs": true, "fuse.encfs": true,
		"fuse.archivemount": true, "fuse.rclone": true,
		"fuse.lxcfs": false, "fuse.fuse-overlayfs": false, "FUSE.LXCFS": false, "fuseblk": false, "ext4": false,
		"fuse.snapfuse": false, "fuse.squashfuse": false, "fuse.squashfuse_ll": false, "fuse.erofsfuse": false,
		"fuse.ntfs-3g": false, "fuse.exfat": false,
		"": false, "overlay": false, "tmpfs": false,
	}
	for fs, want := range cases {
		if got := isNetworkFSType(fs); got != want {
			t.Errorf("isNetworkFSType(%q) = %v, want %v", fs, got, want)
		}
	}
	if len(spec.NetworkFSPrefixes) == 0 || len(spec.LocalFuse) == 0 {
		t.Fatal("network_fs_prefixes or local_fuse missing from spec.json")
	}
}
