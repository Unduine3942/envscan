# envscan acceptance checklist

These checks are for real systems that the automated suite cannot reach. On the dev machine the
suite covers Windows (PowerShell 5.1 and 7, cmd.exe) and `envscan.sh` under dash and bash on
Git-for-Windows. Linux, macOS, z/OS and IBM i are covered only by fixtures and stubs. **z/OS and IBM i
have never run on a real system.**

This checklist covers the scripts in `dist/`: `envscan.sh`, `envscan.ps1`, `envscan.cmd` and
`envscan.js` (Windows Script Host). The static Linux binaries in `dist-bin/` have their own cases,
6 and 7. The Go tests run on the dev machine, but they do not replace a run on a real host or container.

Record the outcome of each case (pass, fail, notes) and send the output folder of any failure,
after you have read it, to the maintainers. The report is redacted, but it still describes the
machine.

## Checks that apply to every case

Run each case as an ordinary, non-admin user, from a local directory that the user can write to.

| # | Check | How |
|---|---|---|
| C1 | Exit code is 0 or 1, never 2 | `echo $?` (Unix), `echo %ERRORLEVEL%` (cmd) |
| C2 | The last line of stdout is the output folder, and it exists | compare with `ls` / `dir` |
| C3 | Exactly four files: `AGENT_BRIEF.md`, `envscan.md`, `envscan.json`, `envscan.log` | `ls` |
| C4 | `AGENT_BRIEF.md` has the sections Platform, Runtimes and tools, Package sources and caches, Blockers and warnings, Where you can write and execute, Network, proxy and TLS, Limits, Not checked | read it |
| C5 | Everything under "Not checked" has a reason that makes sense for this machine | read it |
| C6 | `os.identity`, `hw.memory`, `hw.cpu` match what you know of the machine | `envscan.md` |
| C7 | `envscan.json` is pure ASCII and parses as JSON | `LC_ALL=C grep -c '[^ -~]' envscan.json` gives 0; any JSON tool |
| C8 | No secret values: set `ENVSCAN_CHECK_TOKEN=canary-123` before the run and search for `canary-123` | `grep -r canary-123 <folder>` finds nothing |
| C9 | No network traffic in the default tier | see "Watching for network traffic" |
| C10 | Nothing left in temp | Unix: `ls -d ${TMPDIR:-/tmp}/envscan.*` finds nothing; Windows: `dir %TEMP%\envscan-*` lists no new entries |
| C11 | `--list-probes` prints a footprint and exits 0 without writing anything | run it in an empty directory |
| C12 | A bad option exits 2 with a usage message: `--bogus` | run it |

Run a second time with `--deep` and check C1 to C8 and C10 again. Run `--net` only where your
network team agrees, and check that `net.reachability` lists only proxies and mirrors from local
configuration.

### Watching for network traffic

- **Linux:** `strace -f -e trace=network -o /tmp/es.trace sh envscan.sh`, then
  `grep -c connect /tmp/es.trace` gives 0. strace needs no root for your own processes, but
  `ptrace_scope` or a container may block it. If so, ask the network team for a capture.
- **macOS:** ask the network team, or compare `netstat -an -p tcp` before and during the run.
- **Windows:** Resource Monitor, Network tab, filtered on `powershell.exe` and `cmd.exe`.
- **z/OS, IBM i:** ask the network or system team (for example `netstat` or SMF on z/OS).

## Cases

### 1. Linux

Use at least one glibc distribution (RHEL/Rocky or Debian/Ubuntu) and one musl or minimal one
(Alpine, or a busybox container).

1. `sh envscan.sh`: all common checks.
2. If dash is installed (Debian/Ubuntu) and `/bin/sh` is something else, run `dash envscan.sh` too.
3. Copy the folder to a `noexec` mount, if one exists (often `/tmp` or `/dev/shm`), and run
   `sh envscan.sh` from there. It must work.
4. `fs.mounts` lists NFS or CIFS mounts as network and never reads inside them.
5. In a container: `virt.platform` names the container runtime, and `limits.cgroup` shows the
   container's memory and CPU limits.
6. **PowerShell 7, if installed:**
   `POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off pwsh -NoProfile -File envscan.ps1`.
   The exit code and output folder behave as for `sh`, and `scanner.impl` in `envscan.json` is
   `posix-sh`. `pwsh -NoProfile -File envscan.ps1 --bogus` exits 2.

### 2. macOS

1. `sh envscan.sh`: all common checks. `os.identity` gives the macOS version from
   `sw_vers`, and `hw.cpu` says arm64 or x86_64 correctly. If you run it from a Rosetta
   (x86_64) terminal on Apple silicon, `os.identity` must say the shell is translated.
2. `tls.trust` reports the admin trust settings (certificate names only) without asking for a
   password and without a dialog; the System keychain is not opened.
3. No dialog appears at any point, including privacy (TCC) prompts for Desktop, Documents or
   Downloads. If one does, write down which probe was running (see `envscan.log`).
4. PowerShell 7, if installed: as Linux step 6.

### 3. Windows

1. `envscan.cmd` from cmd.exe: all common checks.
2. Where the execution policy allows it: `powershell -NoProfile -File envscan.ps1`.
3. Where Group Policy blocks scripts: `envscan.cmd` writes `envscan-fallback.txt` and prints
   guidance case 2 or 3 from README section "When Windows blocks the script". It must never print
   the `-ExecutionPolicy Bypass` suggestion when the policy comes from Group Policy.
4. With AppLocker or WDAC: no bypass is attempted, and the fallback runs or the launcher stops.
5. Run from a OneDrive-synced Desktop folder: the output folder goes to your home or temp folder,
   not to the Desktop.

### 3a. Windows Script Host (`envscan.js`)

Ask your security team first: security tools often watch Windows Script Host.

1. On a machine where PowerShell scripts are blocked by a **local** policy (not Group Policy), or
   where `envscan.ps1` was removed from the folder: `envscan.cmd --wsh`. All common checks;
   `scanner.impl` in `envscan.json` is `jscript`, and there is no `envscan-fallback.txt`.
2. Directly: `cscript //nologo //E:jscript envscan.js`. All common checks. No window opens.
3. Where Group Policy enforces the execution policy, or AppLocker/WDAC blocks PowerShell:
   `envscan.cmd --wsh` must NOT run `envscan.js`. The reduced report runs, and its `wsh:` line says why.
4. With Windows Script Host disabled (`HKCU\Software\Microsoft\Windows Script Host\Settings`
   `Enabled` = 0, if you are allowed to set it on a test machine): the reduced report runs, and
   its `wsh:` line says WSH is disabled.
5. Compare with an `envscan.ps1` report of the same machine: the same probes and findings, except
   the documented unknowns (folder permissions, groups and elevation, links not followed, Store
   packages, `net.reachability` `not_applicable`).
6. `envscan.cmd --wsh --out //x` exits 2.

### 4. z/OS UNIX System Services (unverified: first real run)

Use a test LPAR first. Run from an OMVS or SSH session as an ordinary user.

1. **Transfer, method A:** text-mode FTP into a USS directory, then `sh envscan.sh`.
2. **Transfer, method B:** binary transfer, then
   `export _BPXK_AUTOCVT=ON; chtag -tc ISO8859-1 envscan.sh; sh envscan.sh`.
3. Both must pass the common checks C1 to C8. In addition:
   - `ls -T <folder>` shows the four files tagged `t UTF-8` (CCSID 1208).
   - `envscan.log` says the files were converted, or says why not.
   - `os.identity` shows the z/OS release (for example `z/OS 2.5`), not only `OS/390`.
   - `env.vars` shows your own `_CEE_RUNOPTS` and `_BPXK_AUTOCVT`, not the script's.
   - `fs.mounts` lists the zFS file systems; NFS mounts are marked as network.
   - `tools.inventory` finds Java under `/usr/lpp/java` if installed.
4. In a session with a code page other than IBM-1047 (for example IBM-037), if one is
   available: the report stays in that code page, and the log says it was not converted.
5. Things we could not check from the documentation, so please report what you see:
   - the exact `mount` output;
   - whether `iconv -f IBM-1047 -t UTF-8` exists and behaves as documented;
   - whether `_BPXK_AUTOCVT` interferes with the conversion;
   - the install paths of Java, Python (`/usr/lpp/IBM/cyp`), Node (`/usr/lpp/IBM/cnj`) and zopen.

### 5. IBM i (unverified: first real run)

1. **PASE over SSH:** `ssh user@host`, then `sh envscan.sh` (or `/QOpenSys/pkgs/bin/bash envscan.sh`).
   Expect the common checks, and `os.identity` with the IBM i release (`uname -v` and `-r`, for
   example 7.5).
2. **From QSH:** `STRQSH`, then `sh envscan.sh`. Expected: the script restarts in the PASE shell
   and finishes, or exits 2 with "run envscan.sh from PASE". Nothing else, and no garbled output.
3. **PASE from a 5250 session:** `CALL QP2TERM`, then `sh envscan.sh`.
4. `/QNTC` and `/QFileSvr.400` never appear as read in `envscan.md` sources.
5. With `--deep`: four `DSPSYSVAL` results (QSECURITY, QCCSID, QTIMZON, QLANGID) appear as raw output.
6. Please report what you see for:
   - the `mount` / `df` output in PASE;
   - whether QSH can start the PASE shell;
   - the `system` command output format;
   - the open-source package paths under `/QOpenSys/pkgs`.

### 6. Static binary on a Linux host

Use a glibc distribution (RHEL/Rocky or Debian/Ubuntu) first. Run as an ordinary user, from a
local folder that is not `noexec`. Use the binary that matches `uname -m`: `x86_64` gives
`envscan-linux-amd64`, `aarch64` gives `envscan-linux-arm64` (both supported).

1. **Checksums.** In `dist-bin/`, `sha256sum -c SHA256SUMS` prints OK for every binary. Any
   FAILED line or missing file: stop, do not run the binary.
2. Copy the binary, `chmod +x`, run `./envscan-linux-amd64`. All common checks C1 to C8, C10.
3. `ldd envscan-linux-amd64` says "not a dynamic executable" (static). `file`, if installed, says
   "statically linked".
4. Compare with `sh envscan.sh` on the same host: `os.identity`, `hw.cpu` and `hw.memory` agree.
   Differences listed under "Static binary" in `README.dist.md` are expected (for example
   `limits.process` reports the parent's soft limit; users and groups come only from
   `/etc/passwd` and `/etc/group`).
5. Run again with `--deep`: C1 to C8 and C10.
6. `--net` only where your network team agrees: `net.reachability` lists only proxies and mirrors
   from local configuration, and it uses Go's DNS and TCP, with no `curl` or `nc`.
7. **s390x and ppc64le (experimental: first real run).** On a matching host (`uname -m` says
   `s390x` or `ppc64le`), check the binary as in step 1 and run it once with C1 to C8 and C10.
   Report the result even when it passes, and record the `uname -m` and the distribution.

### 7. Static binary in a distroless or scratch container

Use a distroless image (no shell) and, if you have one, a `scratch` image with only the binary.
Run it from a host with Docker. The image needs a writable, exec-capable folder (`/tmp` in these
examples; a `scratch` image has no `/tmp`, so use a folder or volume that it has). Distroless
images run as the `nonroot` user (uid 65532): add `-u 65532:65532` to `docker exec` to run as an
ordinary user, as the common checks ask.

1. **Checksums and architecture.** As in case 6, step 1. Pick the binary for the image's
   architecture (`docker image inspect <image> --format '{{.Architecture}}'`: `amd64` or `arm64`;
   s390x and ppc64le are experimental).
2. On the host: `chmod +x envscan-linux-amd64`, then
   `docker cp envscan-linux-amd64 <container>:/tmp/`.
3. `docker exec <container> /tmp/envscan-linux-amd64 --out /tmp`. Record the exit code (0 or 1;
   2 is a failure). The last line of stdout is the output folder inside the container.
4. Copy the output folder out: `docker cp <container>:<folder> ./envscan-out`.
5. Check the output folder on the host: C2 (the folder printed in step 3 exists), C3 (the four
   files), C4 (`AGENT_BRIEF.md` sections), C7 (`LC_ALL=C grep -c '[^ -~]' envscan.json` gives 0,
   and `envscan.json` parses and is valid against `schema/envscan.schema.json`), and C8 (run step 3
   again with `-e ENVSCAN_CHECK_TOKEN=canary-123` on `docker exec`; `grep -r canary-123` finds
   nothing).
6. **No network traffic in the default tier.** The container has no shell, so watch it from the
   host: tcpdump on its interface, or the network team's capture. Starting the container with
   `--network none` also shows that nothing can leave, but it is not a substitute for the capture.
7. **Nothing left in /tmp** except the output folder and the binary you copied in. The image has
   no `ls`, so use `docker diff <container>`: under `/tmp` it lists only those two (the private
   `envscan.<pid>.<n>` folder is removed at exit and does not show).
8. `docker exec <container> /tmp/envscan-linux-amd64 --list-probes` exits 0 and lists 49 probes:
   `... --list-probes | grep -c '^[a-z]'` prints 49. Nothing is written.
9. `docker exec <container> /tmp/envscan-linux-amd64 --bogus` exits 2 with a usage message (C12).
10. **s390x and ppc64le (experimental: first real run).** Same steps on a matching image. Record
    the result even when it passes.

Run steps 3 to 7 once more with `--deep`.

## Reporting

For each failure, send:
- the case number and the check (for example "4.3, C7");
- the OS and version, the shell, and the exact command line;
- `envscan.log`, and the `envscan.md` section of the probe concerned, after you have read them.
