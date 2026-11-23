# envscan <!-- ENVSCAN:VERSION -->

envscan describes the machine it runs on so that a production team or a coding agent knows
what an application will face there: OS and hardware, the running user's rights, runtimes and
build tools, package sources and offline caches, proxies and certificates, where you can write
and execute, and resource limits.

It needs nothing the operating system does not already ship. No Python, no downloads, no
administrator rights, no installation. By default it sends **no network traffic**.

| File | Purpose |
|---|---|
| `envscan.cmd` | Windows entry point. Starts `envscan.ps1`, or collects a reduced report with cmd.exe alone when PowerShell may not run scripts. |
| `envscan.ps1` | Windows scanner: Windows PowerShell 2.0 to PowerShell 7, also in ConstrainedLanguage mode. On Linux/macOS under PowerShell 7 it only starts `envscan.sh` (see "PowerShell 7 on Linux/macOS"). |
| `envscan.js` | Windows scanner for Windows Script Host (`cscript.exe`), used only when asked for (`envscan.cmd --wsh`) where PowerShell is missing or blocked by a local policy (see "Windows Script Host"). |
| `envscan.sh` | Unix scanner: Linux (glibc, musl, containers, WSL), macOS, BSD, AIX, Solaris; any POSIX `sh`. z/OS UNIX and IBM i PASE are tier 2: best effort, unverified (see "z/OS UNIX and IBM i"). |
| `SHA256SUMS` | Checksums of the files above. |
| `dist-bin/envscan-linux-amd64`, `-arm64`, `-s390x`, `-ppc64le` | Optional static Linux binaries, one per architecture, for hosts and containers with no shell. Not in this folder: see "Static binary" in section 2. |
| `dist-bin/SHA256SUMS` | Checksums of those binaries. |

## 1. Transfer and verify

Copy this folder by whatever route your network allows (approved file transfer, removable
media). All files in this folder are plain text, so they can be reviewed before they enter the
network. The binaries in `dist-bin/` are not text: they are a separate, optional set with their
own `SHA256SUMS` (see "Static binary" in section 2). Check the files against the published
`SHA256SUMS`:

| System | Command |
|---|---|
| Windows, PowerShell 4+ | `Get-FileHash -Algorithm SHA256 envscan.cmd, envscan.js, envscan.ps1, envscan.sh` |
| Windows, any version | `certutil -hashfile envscan.ps1 SHA256` (once per file) |
| Linux | `sha256sum -c SHA256SUMS` |
| macOS | `shasum -a 256 -c SHA256SUMS` |
| Solaris | `digest -a sha256 envscan.sh` |
| AIX and others with OpenSSL | `openssl dgst -sha256 envscan.sh` |
| z/OS UNIX | `sha256 envscan.sh` (or your site's checksum tool); compare before any conversion |

## 2. Run

Windows (from cmd.exe, PowerShell or Explorer):

```
envscan.cmd
```

Unix (no `chmod` needed; works from `noexec` mounts):

```
sh envscan.sh
```

A scan takes about one to two minutes. Results go to a new folder
`envscan-<host>-<UTC time>` under the current directory. They go under your home or temp
directory instead when the current one is not writable, is on the network, or is a Desktop,
Documents or cloud-synced (OneDrive) folder, from where the report could leave the machine.
`--out` is always used as given. The last line printed is that folder's path.

Exit codes: `0` complete; `1` finished but some facts could not be checked (see
"Not checked" in the brief); `2` could not run (bad arguments, no writable output folder).

### Options

| Option | Meaning |
|---|---|
| `--deep` | Also run probes that security tools may notice: `whoami /all`, `gpresult`, `netstat`, `sudo -n -l`, `keytool`, `docker info` (local engine only), and a test that writes and runs a small script in each writable per-user location. Ask your security team first. |
| `--net` | Also test DNS and TCP reachability (3 s each) of proxies and package mirrors found in local configuration. Nothing else is contacted: public registries (npmjs.org, nuget.org, pypi.org, github.com, ...) are listed as skipped without even a DNS lookup; cloud metadata, link-local and public IP addresses are never contacted (only private IPv4 and global or unique-local IPv6). Names without a dot (`proxy:8080`) are listed as skipped and not looked up, because DNS search domains could turn them into another host; write the full name (`proxy.corp.example:8080`) in the configuration to have it checked. |
| `--out DIR` | Parent directory for the output folder. |
| `--only IDS` / `--skip IDS` | Comma-separated probe ids or area wildcards, e.g. `--only "net.*,tls.trust"`. Quote the list: cmd.exe splits arguments at commas, and a Unix shell may expand `*`. |
| `--timeout SEC` | Time limit for each external command (default 15). |
| `--budget SEC` | Time limit for the whole scan (default 600); probes left over are reported as skipped. |
| `--no-redact` | Write secret values instead of `<redacted>` (recorded in the report). |
| `--list-probes` | Print every probe and exactly what it reads or runs, then exit. Useful for an approval review. |
| `--version`, `--help` | Print the version or the usage. |
| `--wsh` | `envscan.cmd` only. When PowerShell or `envscan.ps1` is missing, or a local execution policy (not Group Policy) blocks the script, run `envscan.js` with Windows Script Host (`cscript.exe`) instead of the reduced report. See "When Windows blocks the script". |

### Static binary (Linux hosts and containers with no shell)

`dist-bin/` holds one static binary per Linux architecture. It is the same kind of scan, written
in Go, for hosts and containers that have no shell at all (distroless, scratch). It needs no
interpreter and no shared libraries. Pick the file by `uname -m`:

| `uname -m` | File | Status |
|---|---|---|
| `x86_64` | `envscan-linux-amd64` | supported |
| `aarch64` | `envscan-linux-arm64` | supported |
| `s390x` | `envscan-linux-s390x` | experimental: built and checksummed, never run yet |
| `ppc64le` | `envscan-linux-ppc64le` | experimental: built and checksummed, never run yet |

Verify the copy first. In `dist-bin/`, check all four files with `sha256sum -c SHA256SUMS`, or
only the one you copy:

```
grep envscan-linux-amd64 SHA256SUMS | sha256sum -c -
```

Copy it to a folder that allows execution (not a `noexec` mount), make it executable and run it:

```
chmod +x envscan-linux-amd64
./envscan-linux-amd64 [options]
```

The options, the output folder, the four files (`envscan.json`, `envscan.md`, `AGENT_BRIEF.md`,
`envscan.log`), the exit codes (0, 1, 2) and the last line of stdout (the output folder path) are
the same as for `envscan.sh`. `./envscan-linux-amd64 --list-probes` prints its footprint: 49 probes.

Containers. A `scratch` image has no `/tmp`, so use a writable, exec-capable folder the image has
(or a mounted volume). Copy the binary in and run it there:

```
docker cp envscan-linux-amd64 <container>:/tmp/
docker exec <container> /tmp/envscan-linux-amd64 --out /tmp
```

The last line printed is the output folder inside the container. Copy it out with
`docker cp <container>:<folder> .`.

The binary is not signed. Application control (fapolicyd, SELinux exec rules, `noexec` mounts)
may block it. Ask your security team before you copy it in.

How it differs from `envscan.sh`:

* Linux only. It does not run on macOS, BSD, AIX, Solaris, z/OS or IBM i.
* It reads `/proc`, `/sys` and `/etc` and makes system calls (uname, limits, filesystem stats,
  user and group ids) where that gives the same value as a command. It runs a command only where
  `envscan.sh` does, and only when the command is there.
* Without a shell or some tools, many probes are `partial` or `not_found`. With no `ps`,
  `proc.list` is `partial`. With no `/bin/sh`, `fs.exec_test` skips its script test; that is not
  a `noexec` result.
* User and group names come only from `/etc/passwd` and `/etc/group`. An account that exists only
  in LDAP or SSSD shows as a number, and `passwd_entry` is false.
* "Writable" is judged from mode bits, user and group ids and read-only mounts. ACLs are not seen.
* The Go runtime raises its own soft open-files limit at start. So `limits.process` reports the
  soft limit of the parent process (from `/proc/<ppid>/limits`), and says unknown when that cannot
  be read.
* `--net` uses Go's own DNS resolver and TCP connects; there is no `curl` or `nc`. IP literals are
  not looked up. The address rules of `--net` apply as for the scripts.
* A command that runs past `--timeout` has its whole process group killed at once (SIGKILL).

The s390x and ppc64le binaries have never been run. Treat their first report as a test, as for
z/OS, and report anything that looks wrong.

### z/OS UNIX and IBM i (tier 2: best effort, unverified)

`envscan.sh` has been written from IBM's documentation only. It has **not been run on a real
z/OS or IBM i system**: treat the first report as a test and check it against what you know.
It never guesses; what it cannot read it reports as `partial`, `not_applicable` or `not_found`
with a note. Report anything wrong to the maintainers.

**z/OS UNIX System Services.** The script is ASCII text and z/OS shells read EBCDIC, so the
copy must be converted or tagged on arrival. An untagged ASCII copy fails at its first line,
before the script can do anything.

* Text-mode FTP (or SFTP/scp with conversion) into a USS directory converts it to the
  default code page (IBM-1047). Run it with `sh envscan.sh`.
* Or transfer in **binary**, then tag the file and let z/OS convert on read:

  ```
  export _BPXK_AUTOCVT=ON
  chtag -tc ISO8859-1 envscan.sh
  sh envscan.sh
  ```

The script sets `_BPXK_AUTOCVT=ON` and appends `FILETAG(AUTOCVT,AUTOTAG) POSIX(ON)` to any
existing `_CEE_RUNOPTS` for the commands it starts (your own options stay). It writes its
four report files in IBM-1047, then converts them with `iconv -f IBM-1047 -t UTF-8` and tags
them `chtag -tc 1208`, after checking that the result has line feeds (no NL left as U+0085) and
that `envscan.json` starts with `{`. It only converts when the host code page is IBM-1047 (the
character `[` is the byte `ad`). If the conversion or the check fails, or the code page is
another EBCDIC one such as IBM-037, the files stay in the host code page and the log says so:
the report is never lost. In another code page every character outside printable ASCII shows
as U+FFFD in `envscan.json` and `?` in `envscan.md`. `env.vars` shows your original
`_CEE_RUNOPTS` and `_BPXK_AUTOCVT`, not the values the script sets for its commands. Release
and version come from `uname -I` (plain `uname` gives the OS/390-compatible identity). `envscan.json` is pure ASCII either way. Plain `df` is never
run (it would also ask NFS servers); NFS and other network file systems are never touched.

**IBM i.** Run it from **PASE** (ASCII, AIX-like), not from QSH: connect with `ssh`, or run
`CALL QP2TERM` on a 5250 session, then `sh envscan.sh` (`/QOpenSys/usr/bin/sh` or
`/QOpenSys/pkgs/bin/bash`). QSH runs in the job's EBCDIC CCSID: from there the script starts
the PASE shell when it exists, otherwise it stops with "run envscan.sh from PASE" (exit 2).
`/QNTC` and `/QFileSvr.400` count as network paths and are never touched. With `--deep` it
also displays four system values (`system "DSPSYSVAL SYSVAL(QSECURITY)"`, `QCCSID`, `QTIMZON`,
`QLANGID`; display only) and keeps the text as raw output.

### PowerShell 7 on Linux/macOS

Plain `sh envscan.sh` is the primary route on Linux and macOS. If only PowerShell 7 is wanted,
`envscan.ps1` also runs there: under PowerShell 6+ on Unix it checks the options exactly as on
Windows (a bad option exits 2 with the usual message), then runs `/bin/sh envscan.sh` with the
same arguments. `envscan.sh` must be in the same folder as `envscan.ps1`; otherwise it exits 2
("envscan.sh must be next to envscan.ps1 on Linux/macOS"). stdout (the last line is the output
folder), stderr and the exit code (0, 1, 2) are those of `sh`. Nothing is read from stdin.

pwsh itself contacts Microsoft at startup (telemetry, update check) before any script runs, so
start it with both opt-outs already set:

```
POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off pwsh -NoProfile -File envscan.ps1
```

Needs pwsh 7.3 or later for exact argument passing; on older versions an empty argument or one
containing a double quote is refused (exit 2). Option names are passed to `sh` in lower case. The
output folder path goes through PowerShell's text pipeline, so a path in a non-UTF-8 encoding may be
altered.

`--list-probes`, `--version` and `--help` are forwarded to `sh`, so their output is the footprint
and the version of the `sh` scanner (`envscan <version> (posix-sh)`), and the report says
`impl` `posix-sh`. The Windows-only probes of `envscan.ps1` do not run there.

### When Windows blocks the script

`envscan.cmd` never changes the execution policy, never adds `-ExecutionPolicy` on its own
and never asks for elevation. Before starting PowerShell it predicts from the registry whether
`envscan.ps1` may run, checking:
- the Group Policy, user and machine settings and the defaults;
- the "downloaded from the internet" mark;
- the script's signature.

It also notices when PowerShell refuses the script anyway. In either case it collects a reduced
report with cmd.exe alone (`envscan-fallback.txt`, honouring `--only` and `--skip`). It then
prints your options:

1. **The policy is a local setting or the default, not Group Policy.** If your organization's
   rules allow it, run the full scan once with a process-scoped policy. This changes no setting
   and affects only that one PowerShell process:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File envscan.ps1 [options]`
   - If the file carries the internet mark and RemoteSigned applies, you can instead unblock it
     (Properties, Unblock).
   - On a network share, copy the folder to a local disk first.
   - Or run `envscan.cmd --wsh [options]` (see below).
   - If you are unsure whether this is allowed, ask your security team first.
2. **Group Policy enforces the policy** (for example AllSigned). Do not try to override it. Ask
   IT or security to sign `envscan.ps1` with a trusted code-signing certificate, or to allow it.
3. **PowerShell cannot start or is blocked** by application control (AppLocker, WDAC, Software
   Restriction Policies). Ask IT or security; do not work around it.
4. **Command Prompt is disabled by policy** (`DisableCMD`). Start `envscan.ps1` from
   PowerShell directly.

**Windows Script Host (`--wsh`).** `envscan.cmd --wsh [options]` runs `envscan.js`, the same
scan written in JScript, with `%SystemRoot%\System32\cscript.exe` (never `wscript.exe`). It is
opt-in, and the guidance offers it only where it may be used. `--wsh` is used only when:
- PowerShell or `envscan.ps1` is missing, or the execution policy is a local setting or the
  default (case 1). It is never used when Group Policy enforces the policy (case 2), when the
  policy could not be read, when PowerShell is blocked by application control (case 3), when
  PowerShell started and failed for another reason, or with `--fallback`;
- `cscript.exe` and `envscan.js` exist and a private temporary folder is writable;
- Windows Script Host may run the script: it is not disabled (`Enabled` 0), does not require
  signed scripts (`TrustPolicy` other than 0), and neither Software Restriction Policies nor
  AppLocker script rules are configured. HKLM and HKCU
  `Software\Microsoft\Windows Script Host\Settings` are read; HKLM `IgnoreUserSettings` 1
  makes only HKLM count;
- there is no App Control for Business (WDAC) policy file `System32\CodeIntegrity\SiPolicy.p7b`
  (only its existence is checked) and Smart App Control is off (HKLM
  `SYSTEM\CurrentControlSet\Control\CI\Policy` `VerifiedAndReputablePolicyState` missing or 0).
  WDAC policies in the multiple-policy format (`CiPolicies\Active\*.cip`) are not detected,
  because Windows 11 keeps its own inbox policies there even when nothing is enforced; neither
  is a policy kept only on the EFI system partition. If your organisation uses App Control,
  ask before you use `--wsh`.

When `envscan.js` cannot run or does not finish, the reduced report runs as usual; its `wsh:`
line says why `--wsh` was not used, or that `envscan.js` ended without a result, followed by
the error output of `cscript.exe`. Without `--wsh`, PowerShell is preferred whenever it may run.
An `--out` value that starts with `//` is refused with `--wsh` (every `--out`, when it is
given more than once), because `cscript.exe` would take it as one of its own options.
`cscript.exe` gets the Windows directory and system drive that `envscan.cmd` checked, not
the caller's `SystemRoot` and `SystemDrive` (PowerShell gets them too). Security tools often watch Windows Script Host: ask your
security team before you use it.

`envscan.js` can also be started directly: `cscript //nologo //E:jscript envscan.js [options]`
(same options and exit codes; never with `wscript.exe`). Its report has the same files and
format, with `scanner.impl` `jscript`. Some facts are unknown in it, never guessed, because Windows
Script Host has no way to read them without new tools:
- folder permissions: whether this user may write a PATH folder, Program Files or a personal
  folder is `null`, except where the scan already tests by creating a file;
- the user's groups and whether the session is elevated;
- link targets: symbolic links and junctions (for example Oracle's `javapath`) are never
  followed, so tools reached only through one are not found or not run;
- Store (Appx) packages, and the actions and accounts of scheduled tasks when WMI cannot give them;
- `--net`: no reachability test at all. `net.reachability` lists what `envscan.ps1` would check and
  is `not_applicable`.
`envscan.md`, `AGENT_BRIEF.md` and `envscan.log` are ASCII: a character outside ASCII shows as `?`
there (`envscan.json` keeps it exactly). A scan takes about three minutes.

`envscan.cmd` reserves environment variable names that start with `__ES_`. It checks every
argument before it starts anything, and refuses an argument containing a quote character (and
an `--out` value containing `%`, `<`, `>`, `|`, `*` or `?`). It uses two temporary files in
your temp folder, `envscan-launch-<number>.err` and `.out`, and deletes them after use.

## 3. Read the results

| File | Content |
|---|---|
| `AGENT_BRIEF.md` | Start here. At most about 150 lines, written for a coding agent: platform, runtimes, package sources, blockers and warnings, where you can write and execute, network/proxy/TLS, limits, and what could not be checked. |
| `envscan.md` | Full human-readable report: findings, then one section per probe with its data, sources and raw command output. |
| `envscan.json` | The same as data (schema `envscan/1`), pure ASCII. |
| `envscan.log` | Progress, timing and errors. |
| `envscan-fallback.txt` | Only from the cmd.exe fallback: sectioned text output. |

How to read them:

* **Missing is not absent.** Every probe has a status: `ok`, `partial`, `not_found` (checked,
  does not exist), `not_applicable`, `denied` (needs rights the user does not have),
  `timeout`, `error` or `skipped` (tier not enabled, `--only/--skip`, or time budget).
  Anything other than `ok`, `not_found` or `not_applicable` is listed under "Not checked"
  in the brief, with the reason. Treat those facts as unknown.
* **Scope.** Each probe says whose view it describes: `machine`, `user` or `process`. The
  scan sees the scanning user. A service, scheduled task, IIS application pool or systemd
  unit may run as another account with a different profile, environment, proxy and rights.
* **Findings** combine facts into conclusions with a severity (`blocker`, `warning`,
  `info`), a one-line detail, a fixed recommendation and the probes they are based on.
* **Provenance.** `sources` in every probe lists exactly what was read or run.
* **Secrets** are replaced by `<redacted>`: secret-looking variable names and config keys,
  credentials in URLs, known token formats, authorization headers and private keys.

Where to look:

| Question | Probes |
|---|---|
| What OS, architecture and hardware? | `os.identity`, `hw.*`, `virt.platform`, `session.context` |
| Which runtimes, compilers and tools, which versions? | `tools.inventory`, `runtime.*`, `toolchain.msvc`, `native.deps`, `pkg.installed` |
| How do I get dependencies here? | `pkg.sources`, `pkg.caches`, `net.proxy`, `tls.trust`, `net.reachability` (`--net`) |
| Where can I write, install and execute? | `fs.locations`, `env.path`, `sec.app_control`, `shell.info`, `fs.semantics`, `fs.exec_test` (`--deep`) |
| What limits apply? | `limits.*`, `hw.memory`, `hw.storage`, `net.ports` |
| Who am I and what may I do? | `user.identity`, `user.profile`, `user.privileges` (`--deep`) |

## 4. What envscan never does

* Elevate, prompt, or open a window. Every child process gets empty input and a time limit;
  a process that runs too long is stopped together with its children.
* Send network traffic in the default tier, contact cloud metadata services, query a
  domain controller, query mapped network drives, or contact any host that is not in local
  proxy or package configuration.
* Change anything: no registry, policy or configuration writes. It writes only its output
  folder and short-lived new test files in temp and the per-user locations it reports on,
  never in Desktop, Documents or OneDrive folders (those are judged from their permissions).
* Read antivirus exclusions, the Winlogon, Installer or IPsec policy keys, or LSA settings other
  than the FIPS flag.
* Open or even check for credential stores: SSH keys, cloud CLI credentials, `.netrc`,
  git credential files, container registry logins, shell or PowerShell history.
* Pass your tokens or proxy passwords to the programs it runs: tool version checks see only a
  short list of system variables (PATH, home, temp, locale, tool homes such as JAVA_HOME).
* Touch network file systems, including FUSE mounts it does not know to be local.
* Run version-manager shims, PowerShell script shims, Windows Store app aliases, the WSL
  launcher, or anything marked "inventory only" in the footprint below.

## 5. Footprint: what each probe reads or runs

`--list-probes` prints the same list for the script you run.

<!-- ENVSCAN:FOOTPRINT -->

## 6. Known limits

* Containers without a shell (distroless, scratch) cannot run the scripts. The static Linux binary
  runs there, but many probes are `partial` or `not_found` (see "Static binary" in section 2).
* The static binary is Linux only and differs from `envscan.sh` in the ways listed under its
  section. Its s390x and ppc64le builds have never been run.
* Facts that need administrator rights (BitLocker, firewall rules, other users' command
  lines, antivirus exclusions) are reported as `denied` or left out, never guessed.
* AIX, Solaris, HP-UX and the BSDs get identity, resources and raw command output; deeper
  checks are best effort.
* z/OS UNIX and IBM i PASE are tier 2, unverified: no test system existed. Services, kernel
  settings (BPXPRMxx, system values), RACF users, key rings and Digital Certificate Manager
  stores are not read; the C-locale sort order on EBCDIC (lower case before upper case before
  digits) changes which 500 package names the list keeps.
* The cmd.exe fallback report is reduced. In it, a registry value you may not read shows as
  not set.
* `envscan.js` (Windows Script Host) leaves some facts unknown (see "Windows Script Host" above).
  Application control by WDAC cannot be predicted from the registry: if it stops `cscript.exe`,
  the reduced report runs instead. When `envscan.js` fails after creating its output folder, that
  folder stays next to the one of the reduced report.
* Redaction is pattern-based. It hides too much rather than too little, but it cannot know every
  secret format. Read the output before it leaves the machine. A value or line longer than
  131072 characters is replaced whole by `<redacted: too long>`; a config file in UTF-16 or with
  binary content that `envscan.sh` cannot decode safely is listed but not read.
