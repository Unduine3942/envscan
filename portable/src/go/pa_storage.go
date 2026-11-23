// pa_storage.go: hw.storage and hw.gpu (ports of src/sh/20-os.sh, Linux branches).
//
// hw.storage: sh runs "df -P -k -l". Go asks statfs(2) for each local mount of the mount table
// read at scan start, with df's rules: network types are never queried (df -l), file systems of
// size 0 are hidden, a block device mounted twice is listed once (shortest mount point), and
// sizes are 1024-byte blocks rounded up like df -k before sh's integer division to MiB.
package main

import (
	"strings"
)

type paVolume struct {
	m           Mount
	totKB, avKB uint64
}

func probeHWStorage(e Env, r *Result) {
	r.Src("syscall statfs (local mounts of the mount table)")
	r.Src("mount table read at scan start (file system types)")
	vols, failed := paLocalVolumes(e)
	arr := []any{}
	for _, v := range vols {
		arr = append(arr, paVolumeObj(e, v))
	}
	if len(arr) > 0 {
		r.Src("read /sys/block/*/removable (per volume)")
	}
	r.Data.Set("volumes", arr)
	if failed > 0 {
		r.Note("statfs failed on %d local mount point(s)", failed)
	}
	r.Note("network file systems are not queried; see fs.mounts for every mount")
	if len(arr) == 0 {
		r.Partial("no volume information (statfs failed)")
	}
}

// paSkipMount: network, pseudo (except overlay) and snap mounts are not volumes.
func paSkipMount(e Env, m Mount) bool {
	if isNetworkFSType(m.Type) || (paPseudoFS[m.Type] && m.Type != "overlay") {
		return true
	}
	if strings.HasPrefix(m.Dir, "/snap/") || strings.HasPrefix(m.Dir, "/var/lib/snapd/") {
		return true
	}
	return e.IsNetPath(m.Dir) || e.Refused(m.Dir) != ""
}

func paLocalVolumes(e Env) ([]paVolume, int) {
	vols, failed := []paVolume{}, 0
	byDev := map[string]int{}
	for _, m := range e.Mounts() {
		if paSkipMount(e, m) {
			continue
		}
		st, err := e.Statfs(m.Dir)
		if err != nil {
			failed++
			continue
		}
		if st.Blocks == 0 {
			continue
		}
		v := paVolume{m: m, totKB: paCeilKB(st.Blocks, st.BlockSize), avKB: paCeilKB(st.Bavail, st.BlockSize)}
		if i, seen := byDev[m.Device]; seen && strings.HasPrefix(m.Device, "/") {
			if len(m.Dir) < len(vols[i].m.Dir) {
				vols[i] = v
			}
			continue
		}
		byDev[m.Device] = len(vols)
		vols = append(vols, v)
	}
	return vols, failed
}

func paCeilKB(blocks, size uint64) uint64 {
	b := blocks * size
	return (b + 1023) / 1024
}

func paVolumeObj(e Env, v paVolume) *Obj {
	rem := ""
	if base := paBlockBase(v.m.Device); base != "" {
		if l, ok := paRead1Quiet(e, "/sys/block/"+base+"/removable"); ok {
			switch l {
			case "1":
				rem = "true"
			case "0":
				rem = "false"
			}
		}
	}
	o := NewObj().Set("mount", v.m.Dir).Set("device", v.m.Device).Set("fstype", strOrNil(v.m.Type))
	o.Set("total_mb", v.totKB/1024).Set("free_mb", v.avKB/1024)
	return o.Set("network", isNetworkFSType(v.m.Type)).Set("removable", boolOrNil(rem))
}

// paRead1Quiet: the first line of a small file, without sources or notes (sh es_read1 alone).
func paRead1Quiet(e Env, p string) (string, bool) {
	text, _, err := e.ReadText(p, 65536)
	if err != nil {
		return "", false
	}
	return paFirstLine(text)
}

// paBlockBase is sh es_block_base: /dev/sda1 -> sda, /dev/nvme0n1p2 -> nvme0n1.
func paBlockBase(dev string) string {
	t := strings.TrimPrefix(dev, "/dev/")
	if t == "" || strings.Contains(t, "/") {
		return ""
	}
	switch {
	case strings.HasPrefix(t, "nvme") || strings.HasPrefix(t, "mmcblk"):
		if i := strings.LastIndex(t, "p"); i > 0 && i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' {
			return t[:i]
		}
		return ""
	case strings.HasPrefix(t, "sd") || strings.HasPrefix(t, "vd") || strings.HasPrefix(t, "xvd") || strings.HasPrefix(t, "hd"):
		return strings.TrimRight(t, "0123456789")
	}
	return ""
}

// ---------------------------------------------------------------- hw.gpu

func probeHWGPU(e Env, r *Result) {
	gpus := []any{}
	tools, tried := false, false
	opt := RunOpt{}
	if c, ok := needTool(e, r, opt, "nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"); ok {
		tools = true
		gpus = append(gpus, paNvidiaGPUs(c.Stdout)...)
	} else if c.Exit != 126 && c.Exit != 127 {
		tried = true
	}
	if c, ok := needTool(e, r, opt, "lspci"); ok {
		tools = true
		gpus = append(gpus, paLspciGPUs(c.Stdout)...)
	} else if c.Exit != 126 && c.Exit != 127 {
		tried = true
	}
	r.Data.Set("gpus", gpus)
	dri := []any{}
	if paIsDir(e, "/dev/dri") {
		r.Src("list /dev/dri")
		if ents, _, err := e.ReadDir("/dev/dri", 0); err == nil {
			for _, d := range ents {
				dri = append(dri, d.Name)
			}
		}
	}
	r.Data.Set("dri_nodes", dri)
	if len(gpus) == 0 {
		switch {
		case tools || len(dri) > 0:
			if len(dri) > 0 {
				r.Note("render nodes exist in /dev/dri but no adapter details were available")
			} else if !tried {
				r.SetStatus(StNotFound, "")
			}
		case !tried:
			r.Partial("no GPU query tool (nvidia-smi, lspci) is available")
		}
	}
	r.Fact("gpu_count", itoa(len(gpus)))
}

func paNvidiaGPUs(out string) []any {
	res := []any{}
	for _, l := range lines(out) {
		f := strings.SplitN(l, ",", 3)
		for len(f) < 3 {
			f = append(f, "")
		}
		name := paTrim(f[0])
		if name == "" {
			continue
		}
		mem, _, _ := strings.Cut(paTrim(f[2]), " ")
		res = append(res, NewObj().Set("name", name).Set("driver_version", strOrNil(paTrim(f[1]))).
			Set("vram_mb", num(mem)).Set("source", "nvidia-smi"))
	}
	return res
}

func paLspciGPUs(out string) []any {
	res := []any{}
	for _, l := range lines(out) {
		if !strings.Contains(l, "VGA compatible controller") && !strings.Contains(l, "3D controller") &&
			!strings.Contains(l, "Display controller") {
			continue
		}
		// awk sub(/^[^:]*:[^:]*: */, ""): drop up to the second colon and the blanks after it
		name := l
		if parts := strings.SplitN(l, ":", 3); len(parts) == 3 {
			name = strings.TrimLeft(parts[2], " ")
		}
		if name == "" {
			continue
		}
		res = append(res, NewObj().Set("name", name).Set("driver_version", nil).Set("vram_mb", nil).Set("source", "lspci"))
	}
	return res
}
