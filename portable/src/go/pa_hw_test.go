package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const paCPUInfoX86 = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz
physical id	: 0
cpu cores	: 2
flags		: fpu sse4_2 avx avx2 aes

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz
physical id	: 0
cpu cores	: 2
flags		: fpu sse4_2 avx avx2 aes
`

const paCPUInfoARM = `processor	: 0
BogoMIPS	: 50.00
Features	: fp asimd aes crc32
CPU implementer	: 0x41

processor	: 1
Features	: fp asimd aes crc32
CPU implementer	: 0x41
`

func TestCPUx86(t *testing.T) {
	e := newFakeEnv(t, paTree(t, map[string]string{"proc/cpuinfo": paCPUInfoX86}))
	r := paRun(t, e, "hw.cpu")
	paWant(t, r, map[string]any{"model": "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz", "vendor": "GenuineIntel",
		"cores": "2", "logical": "2", "sockets": "1", "flags": []any{"fpu", "sse4_2", "avx", "avx2", "aes"},
		"features": map[string]any{"sse4_2": true, "avx": true, "avx2": true, "avx512f": false, "aes": true, "neon": false}})
	if r.Status != StOK || r.Facts["cpu_avx2"] != "true" || r.Facts["cpu_logical"] != "2" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}

func TestCPUarm64NoModel(t *testing.T) {
	e := newFakeEnv(t, paTree(t, map[string]string{"proc/cpuinfo": paCPUInfoARM}))
	e.ArchName = "arm64"
	r := paRun(t, e, "hw.cpu")
	paWant(t, r, map[string]any{"model": "unknown", "vendor": "arm implementer 0x41", "cores": "2", "logical": "2",
		"sockets": nil, "features": map[string]any{"sse4_2": false, "avx": false, "avx2": false, "avx512f": false,
			"aes": true, "neon": true}})
	if r.Status != StPartial || r.Facts["cpu_avx2"] != "false" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}

func TestCPULogicalFallbacks(t *testing.T) {
	e := newFakeEnv(t, paTree(t, map[string]string{"sys/devices/system/cpu/online": "0-3,6\n"}))
	r := paRun(t, e, "hw.cpu")
	paWant(t, r, map[string]any{"logical": "5", "cores": "5", "model": "unknown",
		"features": map[string]any{"sse4_2": nil, "avx": nil, "avx2": nil, "avx512f": nil, "aes": nil, "neon": nil}})
	e = newFakeEnv(t, t.TempDir())
	e.PathBins["getconf"] = "/usr/bin/getconf"
	e.Cmds["getconf _NPROCESSORS_ONLN"] = fakeCmd{Stdout: "8\n"}
	paWant(t, paRun(t, e, "hw.cpu"), map[string]any{"logical": "8"})
	for in, want := range map[string]string{"0": "1", "0-7": "8", "x": "", "3-1": "", "0-a": ""} {
		if got := paOnlineCPUs(in); got != want {
			t.Errorf("online %q = %q", in, got)
		}
	}
}

func TestMemory(t *testing.T) {
	mi := "MemTotal:       16303428 kB\nMemFree:  1000 kB\nMemAvailable:   10485760 kB\nSwapTotal: 2097152 kB\nSwapFree: 1048576 kB\n"
	e := newFakeEnv(t, paTree(t, map[string]string{"proc/meminfo": mi}))
	r := paRun(t, e, "hw.memory")
	paWant(t, r, map[string]any{"total_mb": "15921", "available_mb": "10240", "swap_total_mb": "2048", "swap_free_mb": "1024"})
	if r.Status != StOK {
		t.Error(r.Status)
	}
	old := "MemTotal: 2048 kB\nMemFree: 512 kB\nBuffers: 256 kB\nCached: 256 kB\n"
	e = newFakeEnv(t, paTree(t, map[string]string{"proc/meminfo": old}))
	paWant(t, paRun(t, e, "hw.memory"), map[string]any{"total_mb": "2", "available_mb": "1", "swap_total_mb": nil})
	e = newFakeEnv(t, t.TempDir())
	e.PathBins["getconf"] = "/usr/bin/getconf"
	e.Cmds["getconf _PHYS_PAGES"] = fakeCmd{Stdout: "4096000\n"}
	e.Cmds["getconf PAGESIZE"] = fakeCmd{Stdout: "4096\n"}
	r = paRun(t, e, "hw.memory")
	paWant(t, r, map[string]any{"total_mb": "16000", "available_mb": nil})
	if r.Status != StOK || !paHasNote(r, "available memory is not reported") {
		t.Errorf("status %s notes %v", r.Status, r.Notes)
	}
}

// paDfToFake turns a df -P -k output and a /proc/self/mounts text into a mount table and statfs
// answers in 1024-byte blocks.
func paDfToFake(e *fakeEnv, df, mounts string) {
	for _, l := range lines(mounts) {
		f := strings.Fields(l)
		e.MountTab = append(e.MountTab, Mount{Device: f[0], Dir: f[1], Type: f[2], Options: f[3]})
	}
	for i, l := range lines(df) {
		f := strings.Fields(l)
		if i == 0 || len(f) < 6 {
			continue
		}
		tot, _ := strconv.ParseUint(f[1], 10, 64)
		av, _ := strconv.ParseUint(f[3], 10, 64)
		e.Fs[f[len(f)-1]] = Statfs{BlockSize: 1024, Blocks: tot, Bavail: av}
	}
}

// TestStorageCommandCases: the Linux df cases of tests/data/commands.json (shared with sh).
func TestStorageCommandCases(t *testing.T) {
	for _, c := range paCommandCases(t, "df") {
		name := c["name"].(string)
		if c["os"] != "linux" || name == "volume_missing_from_mount_table" {
			continue // statfs sees only mounts of the mount table (documented difference)
		}
		t.Run(name, func(t *testing.T) {
			e := newFakeEnv(t, t.TempDir())
			paDfToFake(e, c["output"].(string), c["mounts_proc"].(string))
			r := paRun(t, e, "hw.storage")
			got := []any{}
			for _, v := range paPlain(mustGet(r, "volumes")).([]any) {
				m := v.(map[string]any)
				got = append(got, map[string]any{"device": m["device"], "mount": m["mount"], "fstype": m["fstype"],
					"total_mb": m["total_mb"], "free_mb": m["free_mb"]})
			}
			want := paJSONPlain(c["facts"].(map[string]any)["volumes"])
			if !reflect.DeepEqual(got, want) {
				t.Errorf("volumes %v, want %v", got, want)
			}
		})
	}
}

func TestStorageSkipsNetworkPseudoAndDuplicates(t *testing.T) {
	root := paTree(t, map[string]string{"sys/block/sdb/removable": "1\n", "sys/block/nvme0n1/removable": "0\n"})
	e := newFakeEnv(t, root)
	e.MountTab = []Mount{{"/dev/nvme0n1p2", "/", "ext4", "rw"}, {"srv:/x", "/net/x", "nfs4", "rw"},
		{"/dev/sdb1", "/media/usb", "vfat", "rw"}, {"/dev/sdb1", "/media", "vfat", "rw"},
		{"overlay", "/var/lib/docker/overlay2/a/merged", "overlay", "rw"}, {"cgroup2", "/sys/fs/cgroup", "cgroup2", "rw"},
		{"/dev/loop0", "/snap/core/1", "squashfs", "ro"}, {"tmpfs", "/run/empty", "tmpfs", "rw"}, {"/dev/sdc1", "/bad", "xfs", "rw"}}
	e.NetPaths = []string{"/net"}
	e.Fs["/"] = Statfs{BlockSize: 4096, Blocks: 262144, Bavail: 131072}
	e.Fs["/net/x"] = Statfs{BlockSize: 4096, Blocks: 1, Bavail: 1}
	e.Fs["/media/usb"] = Statfs{BlockSize: 512, Blocks: 4096, Bavail: 2048}
	e.Fs["/media"] = Statfs{BlockSize: 512, Blocks: 4096, Bavail: 2048}
	e.Fs["/var/lib/docker/overlay2/a/merged"] = Statfs{BlockSize: 4096, Blocks: 256, Bavail: 256}
	e.Fs["/run/empty"] = Statfs{BlockSize: 4096}
	r := paRun(t, e, "hw.storage")
	vols := paPlain(mustGet(r, "volumes")).([]any)
	mounts := []string{}
	for _, v := range vols {
		mounts = append(mounts, v.(map[string]any)["mount"].(string))
	}
	if strings.Join(mounts, ",") != "/,/media,/var/lib/docker/overlay2/a/merged" {
		t.Fatalf("mounts %v", mounts)
	}
	root0, usb := vols[0].(map[string]any), vols[1].(map[string]any)
	if root0["total_mb"] != "1024" || root0["free_mb"] != "512" || root0["removable"] != false || usb["removable"] != true {
		t.Errorf("volumes %v", vols)
	}
	if !paHasNote(r, "statfs failed on 1") || r.Status != StOK {
		t.Errorf("status %s notes %v", r.Status, r.Notes)
	}
	empty := newFakeEnv(t, "")
	if r := paRun(t, empty, "hw.storage"); r.Status != StPartial {
		t.Errorf("no mounts: %s", r.Status)
	}
}

func TestBlockBase(t *testing.T) {
	for in, want := range map[string]string{"/dev/sda1": "sda", "/dev/nvme0n1p2": "nvme0n1", "/dev/mmcblk0p1": "mmcblk0",
		"/dev/mapper/x": "", "tmpfs": "", "/dev/xvdf": "xvdf", "/dev/nvme0n1": ""} {
		if got := paBlockBase(in); got != want {
			t.Errorf("%s -> %q", in, got)
		}
	}
}

func TestGPU(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	r := paRun(t, e, "hw.gpu")
	if r.Status != StPartial || !paHasNote(r, "no GPU query tool") {
		t.Errorf("no tools: %s %v", r.Status, r.Notes)
	}
	e.PathBins["nvidia-smi"] = "/usr/bin/nvidia-smi"
	e.Cmds["nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader"] =
		fakeCmd{Stdout: "NVIDIA A100-SXM4-40GB, 535.104.05, 40960 MiB\n"}
	e.PathBins["lspci"] = "/usr/bin/lspci"
	e.Cmds["lspci"] = fakeCmd{Stdout: "00:02.0 VGA compatible controller: Intel Corporation UHD Graphics 630\n" +
		"00:1f.3 Audio device: Intel Corporation Cannon Lake PCH cAVS\n"}
	r = paRun(t, e, "hw.gpu")
	want := []any{map[string]any{"name": "NVIDIA A100-SXM4-40GB", "driver_version": "535.104.05", "vram_mb": "40960",
		"source": "nvidia-smi"}, map[string]any{"name": "Intel Corporation UHD Graphics 630", "driver_version": nil,
		"vram_mb": nil, "source": "lspci"}}
	paWant(t, r, map[string]any{"gpus": want, "dri_nodes": []any{}})
	if r.Facts["gpu_count"] != "2" || r.Status != StOK {
		t.Errorf("facts %v status %s", r.Facts, r.Status)
	}
	e.Cmds["nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader"] = fakeCmd{Exit: 9}
	e.Cmds["lspci"] = fakeCmd{Stdout: "00:1f.3 Audio device: x\n"}
	r = paRun(t, e, "hw.gpu")
	if r.Status != StPartial || !paHasNote(r, "failed (exit status 9)") {
		t.Errorf("failing tool: %s %v", r.Status, r.Notes)
	}
	delete(e.PathBins, "nvidia-smi")
	r = paRun(t, e, "hw.gpu")
	if r.Status != StNotFound {
		t.Errorf("lspci without GPUs: %s", r.Status)
	}
	e.Root = paTree(t, map[string]string{"dev/dri/renderD128": ""})
	r = paRun(t, e, "hw.gpu")
	if r.Status != StOK || !paHasNote(r, "render nodes exist") {
		t.Errorf("dri: %s %v", r.Status, r.Notes)
	}
}
