# Developing envscan

envscan is three scripts and one static binary generated from one spec:

| File | Runs on | Source |
|---|---|---|
| `envscan.ps1` | Windows PowerShell 2.0 - PowerShell 7, FullLanguage and ConstrainedLanguage | `src/ps/*.ps1` |
| `envscan.sh` | any POSIX `sh` (dash, bash, ksh, busybox ash, macOS, AIX, Solaris xpg4; z/OS UNIX and IBM i PASE: tier 2, unverified) | `src/sh/*.sh` |
| `envscan.cmd` | Windows launcher + reduced fallback collector (cmd.exe only) | `src/cmd/NN-*.cmd` |
| `envscan-linux-<arch>` (`dist-bin/`) | static Linux binary, no shell or interpreter needed: amd64 and arm64 supported; s390x and ppc64le experimental; darwin deferred | `src/go/*.go` (Go, see "Go" in the Portability checklist) |

`python tools/build.py` validates `spec/*.toml`, assembles each script (module files in name
order, the generated spec block inserted after the `00-*` module), lints it, and writes
`dist/` (the bundle), `build/lib/` (test libraries without the `9x-*` main module) and
`docs/PROBES.md`. The binaries go to `dist-bin/` (see "Script and binary targets" below).
`python -m pytest tests` runs every test. Never edit `dist/` or `dist-bin/` by hand.

## Implementation registry

`REGISTRY` in `tools/spec.py` is the one list of implementations. A row is
`Impl(id, label, kind, dist_file, column, report_impl)`:

| Field | Meaning |
|---|---|
| `id` | short id: footprint file name, `--targets` value, `spec.probes_for(id)` |
| `label` | heading in the footprint docs |
| `kind` | `script` (text file in `dist/`) or `binary` (built into `dist-bin/`) |
| `dist_file` | file name of a script; name prefix of a binary's files |
| `column` | header of its column in the probe table of `docs/PROBES.md` |
| `report_impl` | `scanner.impl` in its JSON report (None: no JSON, like the cmd fallback) |
| `outputs` | binary only: the file names it builds below `dist-bin/`, e.g. one per os/arch. The build fails if one is missing or an undeclared one appears |

The `go` row is the static binary: `kind` `binary`, `dist_file` `envscan`, `outputs`
`envscan-linux-amd64`, `envscan-linux-arm64`, `envscan-linux-s390x`, `envscan-linux-ppc64le`, and
`report_impl` `go`. Its builder is `tools/target_go.py`.

The footprint loader, the validator, the docs headings and column header, `ALL_TARGETS`,
`DIST_FILES` and the `SHA256SUMS` lists in `tools/build.py` all derive from it.
A registered id without `spec/footprint/<id>.toml` is a spec error, never a silent gap.

To add an implementation:
1. Add a row to `REGISTRY` (and its `report_impl` to the `scanner.impl` enum in
   `schema/envscan.schema.json`).
2. Write `spec/footprint/<id>.toml`: one entry per probe it implements, as for `ps`.
3. Write a builder `(spec, root, errors) -> {relative path: bytes}` and add it to `BUILDERS` in
   `tools/build.py`. A `binary` builder returns only paths below `dist-bin/`, and raises
   `ToolchainMissing("how to get the compiler")` when its toolchain is absent.
4. Make its `--list-probes` print exactly `spec.probes_for(id)` (see the format below) and
   add its comparison to the tests (`tests/conftest.py` `expected_probe_listing`).

PowerShell 7 on Linux/macOS is not an implementation and has no registry row. `src/ps/05-unix-shim.ps1`
makes `envscan.ps1` a shim there: after the options are validated (like on Windows) it runs
`/bin/sh <dir of envscan.ps1>/envscan.sh <args>` with an empty stdin, and passes stdout, stderr
and the exit code through. The report is sh's, so `scanner.impl` is `posix-sh`; `--version`,
`--help` and `--list-probes` are forwarded and print the sh output. Detection is
`$PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -eq 'Unix'` (never
`$IsWindows`, which is `$null` on 5.1).
- Option names are forwarded as sh spells them: PowerShell reads `--DEEP` and `-Net`, sh only
  `--deep`/`-deep` in lower case, so the shim sends `--deep`, `--net`, `--only=x` and `--help`
  for `-h`. Values are never changed.
- Exact native arguments need pwsh 7.3+. 5.1 and 6.x to 7.2 drop empty strings and strip embedded
  double quotes when they start a native program, so on those versions the shim refuses an empty
  argument or one with a `"` (exit 2, "use sh envscan.sh").
- stdout goes through PowerShell's text pipeline, so an output path in a non-UTF-8 encoding may
  be altered. `$LASTEXITCODE` is reset before the call.
- Test hooks (read only when `ENVSCAN_TEST_PLATFORM=unix`; they are not recorded in the report,
  which is sh's, but announced on stderr): `ENVSCAN_TEST_PLATFORM=unix` forces the shim;
  `ENVSCAN_TEST_SH=<path>` replaces `/bin/sh` and is required when the real platform is not
  Unix. It must be an absolute local path (no UNC or network drive, no credential store) named
  `sh`, `dash` or `bash` (with or without `.exe`), else exit 2: a hook must never run an
  arbitrary program. `tests/test_ps_unix_shim.py` uses them on Windows.
- pwsh must be started with `POWERSHELL_TELEMETRY_OPTOUT=1` and `POWERSHELL_UPDATECHECK=Off`;
  the tests do that.

Script and binary targets are built apart:
* Script targets (`ps`, `sh`, `cmd`, `js`) are the default of `build()`, `--check` and the
  test `built` fixture. `dist/` stays plain text; `dist/SHA256SUMS` covers the scripts and
  `README.md` only.
* Binary targets (`go`) write to `dist-bin/` with their own `dist-bin/SHA256SUMS`. A binary target is
  built with `python tools/build.py --targets go` (a binary-only build writes nothing to
  `dist/`), or by the release build.
* The release build (`python tools/build.py`, no `--check`) builds every registered target and
  stops with "binary toolchain missing: ..." when a compiler is absent; nothing is written then.
  `--check` builds no binary and never needs a binary toolchain; the tests do not need one either
  (the Go tests skip without it).
* `--targets` without `--check` must name a whole set (every script target and/or every binary
  target), because each `SHA256SUMS` must cover its whole set.

## Hard rules (all implementations)

1. **No network traffic in the default tier.** Only `--net` may resolve names or open sockets,
   and only to proxies and mirrors found in local proxy/package configuration. Never domain
   queries (`net ... /domain`, `nltest`, LDAP). Two spec lists in `spec/configs.toml` bound `--net`
   in both scripts (generated as `ES_PUBLIC_HOSTS` and `ES_NET_NEVER`):
   - `public_hosts`: public registries and code hosts. A configured endpoint under one of these
     suffixes is skipped before any DNS lookup; from an enclave it would be an internet attempt.
   - `net_never`: instance-metadata services and link-local addresses (IMDS 169.254.169.254,
     `fd00:ec2::254`, `metadata.google.internal`, ...). Checked on the configured name and again on
     every resolved address. An entry ending in `.` or `:` is a prefix.
   - The TCP check connects to the vetted address, never to the name, so a second DNS answer
     cannot redirect it. At most 20 endpoints are looked up; skipped ones do not count.
   - Without a resolver command (sh: no `getent` or `dscacheutil`), names are not contacted
     (`tcp: "skipped"`), but IP literals still are. A failed or timed-out lookup is
     `tcp: "error"`. Both make the probe `partial`; only a definitive "no address" is
     `unresolved`.
   - An IPv4 address, literal or resolved, is contacted only in 10/8, 172.16/12, 192.168/16 or
     100.64/10; any other gets `tcp: "skipped"`, "public IPv4 address; never contacted". A name
     with several addresses uses the first allowed one.
   - An IPv6 address, literal or resolved, is contacted only when it is global unicast (first
     hextet 2000-3fff) or unique local (fc00-fdff), and not in `fd00:ec2::/32`. This refuses
     link-local `fe80::/10`, IPv4-mapped `::ffff:`, NAT64 `64:ff9b::`, loopback and multicast in
     any spelling, so text matching against `net_never` alone cannot be bypassed.
   - A single-label name (no "." once one trailing dot is removed: `proxy`, `localhost`) is never
     looked up: `tcp: "skipped"`, "single-label name; DNS search domains could expand it, so it
     is not looked up". Every other name is looked up in its absolute form (`name.`), so no DNS
     search list, `ndots` or Windows suffix devolution can turn it into another host. A name
     that is empty, starts with "." or contains ".." is skipped ("malformed host name; not
     looked up"); an IPv4 literal written with a trailing dot is skipped as a public IPv4 address;
     IP literals are never handed to a resolver.
2. **Read-only.** The only writes are the output folder and self-deleting test files in temp,
   LocalAppData or the candidate directories of `fs.locations`. Never write to Desktop, Documents
   or OneDrive/synced folders; those are judged from their ACL.
   - Create test files exclusively, without `-Force` or `set -C`, so an existing file or link is
     never reused or followed.
   - Delete them in `finally` or a `trap`.
   - The deep exec test runs only in per-user locations.
   - The default output folder (cwd, then home, then temp) skips network, OneDrive/synced,
     Desktop and Documents folders; `--out` is used as given.
   - Never modify the registry, user config, or any file the scanner did not create.
3. **No elevation, no prompts, no GUI.** stdin of every child is empty; every child has a
   timeout; never `sudo` except `sudo -n -l` in `--deep`; never trigger UAC.
4. **Never open or existence-check credential stores**: `~/.ssh`, `~/.aws`, `~/.kube`, `.netrc`,
   `.git-credentials`, `~/.docker/config.json`, `auth.json`, shell/PSReadLine history, k8s
   service-account tokens, private keys. No `find`/permission sweeps of the file system.
   The full list lives in `spec/policy.toml` `[credentials]` (generated into sh `es_cred_folder_hit`,
   `es_cred_file_hit` and `es_cred_key_ext`, and into the `ES_CRED_*` arrays that ps1
   `Test-EsCredentialPath` turns into regular expressions). It also covers `.gnupg`, `.azure`,
   `.config/gcloud`, `.pgpass`, `.vault-token`, `.pypirc`, `.config/gh/hosts.yml`,
   `.terraform.d/credentials.tfrc.json`, `.gem/credentials`, `.cargo/credentials.toml`,
   `.m2/settings-security.xml`, `serviceaccount/token`, `id_rsa`/`id_ecdsa`/`id_ed25519` and files
   ending `.pem .key .p12 .pfx .jks .keystore`, except CA trust stores (`cacerts`, the spec CA
   bundles; sh also exempts `.pem` under system CA folders). Matching ignores case and trailing
   dots or spaces; ps1 also refuses `:stream` suffixes and 8.3 names of these folders. A link
   whose target is a credential store is never followed ("<path> not read: link to a
   credential store", probe `partial`).
   A path that comes from configuration or the environment (a git `include.path`, a spec path
   with `{env:X}`, a resolved link) is checked against this list before it is tested, followed
   or opened (sh `es_cred_path` in `11-policy.sh`; the ps1 uses the same spec data). Add a
   store to `spec/policy.toml`, never to one script.
5. **Never execute** (inventory only): version-manager shims (spec `version_managers`), `.ps1`
   shims, 0-byte WindowsApps aliases, macOS `/usr/bin` developer shims when `xcode-select -p`
   fails, `/usr/bin/java` on macOS when `/usr/libexec/java_home` fails, WSL `/mnt/*` binaries,
   docker when `DOCKER_HOST` is `tcp://`/`ssh://`, tools with `mode = "presence"`.
   `docker info` (deep) always passes `--context default`. `podman info` is never run, because
   podman connections may use ssh.
6. **Children run** from the filesystem root (`%SystemDrive%\` or `/`), with stdin from an empty
   file, with `spec/child_env.toml` applied (after `env.vars` captured the original environment).
   Children see only the user variables listed in `[child_env_keep]` (names, plus prefixes such as
   `LC_` and `XDG_`; exact on Unix, any case on Windows), then the `[child_env]` overrides and
   each probe's own extras. Proxy variables, tokens, `LD_PRELOAD`, `NODE_OPTIONS`,
   `JAVA_TOOL_OPTIONS`, `BASH_ENV`, `ENV`, `DOCKER_HOST` and everything else stay out. A tool
   that needs another variable to start gets it added to that list, never per script.
   Kept variables holding paths are vetted like every other path, without touching them:
   `home_paths` (HOME, USERPROFILE, APPDATA, TMPDIR, ...) on a network mount, UNC path, mapped
   network drive or credential store are replaced by an empty folder in the scanner's private temp
   folder; refused entries of `path_lists` (PATH, LD_LIBRARY_PATH, PSModulePath, ...) are dropped;
   any other kept absolute-path value that is refused is removed.
   The exception is git, which runs from the scanner's own temp folder (rule 12). sh children
   run with `LC_ALL=C`, so localized output (`id` group names, `df` headers) parses the same
   everywhere. Only `os.time_locale` runs its commands in the user's locale
   (`ES_CHILD_LOCALE=user`).
7. **Redact before writing.** The rules are in the header of `spec/redaction.toml`. The ps1
   implementation is `src/ps/14-redact.ps1` (XML rules in `src/ps/14-redact-xml.ps1`); its cases are in `tests/test_ps_redaction.py`.
   - Config files are redacted as whole texts, which covers blocks and private keys.
   - Command-line rules apply to process, service and task command lines, environment and
     registry values, probe `sources` and the log.
   - Every string in probe data passes the value rules as a safety net.
   - `--no-redact` disables redaction and is recorded in `run.redaction = false`.
8. **Every probe is isolated.** A failure sets the probe's status and the scan continues.
9. **Status vocabulary**: `ok` (complete), `partial` (some facts missing; say which in `notes`),
   `not_found` (the thing does not exist here, e.g. no Java), `not_applicable` (does not apply to
   this OS/edition), `denied` (access denied without admin), `timeout`, `error`, `skipped`
   (tier not enabled, `--only/--skip`, or budget exhausted; `notes` says why).
   Absence must be explicit: never leave a fact out silently when it could not be checked.
   A registry key the user may not read makes an otherwise `ok`/`not_found` probe `partial`, with
   the note "access denied to N registry key(s): ..." (ps1: `Add-EsDeniedRead`, reset per probe).
   Keys that stock Windows denies to every standard user and that are out of scope are skipped
   instead (`ES_POLICY_SKIP_RE`), so the exit code keeps its meaning.
10. **Keep every fact's provenance**: `sources` lists what was read or run (short strings).
11. **Absence needs a completed source.** Before printing "none" or "not found", or raising a
    finding based on absence, check the status of the probe that holds the data. When that
    probe did not complete, report unknown or "not checked":
    - ps1: `Test-EsDependency` marks the dependent probe `error`.
    - The brief uses `Get-EsNoneText`.
    A tool that exits non-zero or prints nothing makes the probe `partial`, never `ok` with
    empty data (`Invoke-EsTool`; `-AllowFailure` only where empty output is valid).
12. **Never touch a network path.**
    - Mapped drives come from the PowerShell drive list and `HKCU\Network`. Never use
      `Win32_LogicalDisk`, which asks the file server for size and free space; `hw.storage`
      uses `Win32_Volume`.
    - Every path taken from the spec, the environment or the registry must be absolute and local
      before `Test-Path`, `Get-Acl` or a glob (ps1 `Test-EsLocalPath`: drive letter and `\`, not
      a mapped network drive). Relative, root-relative (`\x`), drive-relative (`C:x`) and UNC
      paths are dropped, and so is `~` when the home variable is empty. Glob results are checked
      again.
    - Child processes that discover repositories (git) run from the scanner's own temp folder,
      with `GIT_CEILING_DIRECTORIES` set to its parent.
    - git reads its global configuration from HOME (Windows: else HOMEDRIVE+HOMEPATH, else
      USERPROFILE), `XDG_CONFIG_HOME` and `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`. When one of
      them is on a network path, that git child gets a scratch HOME in the scanner's temp folder
      and the probe is `partial`. `git config` runs with `--no-includes`. Each unconditional
      `include.path` that resolves to a local file is read one level deep with `--file`. Any
      other unconditional include makes the probe `partial` with the note
      "git include not read (<reason>): <path>". `includeIf` entries get a note only, because
      their conditions cannot match from the filesystem root. Reasons: `network path`,
      `not a local path`, `credential store`, `unreadable`, `nested include`,
      `condition <cond>`. A `~/` include expands with the user's real home, not with the
      scratch HOME. git C-quotes an origin path that holds a backslash or a non-ASCII byte. The
      ps1 decodes those origins, which is common on Windows. The sh treats a quoted origin as
      `not a local path`.
    - Links are followed only to local targets. Before a file or folder is read or listed, it
      and its parent folders are checked for links (sh `es_resolve`; ps1 `Get-EsLinkReason`,
      with one `Get-Item` per folder per scan). A link to a network path, to a credential store,
      or with an unknown target (PS 2-4 cannot read link targets) is not read. The probe gets
      the note "<path> not read: link to a network path | link to a credential store | link
      target unknown" and becomes `partial`. Tools found on PATH or in known folders are
      vetted the same way before they are tested or run.
    - Spec paths are per platform. `os = "all"` entries mix Unix and Windows locations, so
      `tools/target_ps.py` drops Unix-absolute paths from the Windows tables: on Windows,
      `/usr/local/go/bin` would be a root-relative folder on whatever drive the scan runs from,
      which any user may create (or a share, when started from a mapped drive).
13. **ps1 exit codes vs. the launcher.** `envscan.cmd` treats exit code 1 together with
    `UnauthorizedAccess`/`PSSecurityException` on stderr as "PowerShell refused the script".
    So the ps1 keeps error records off stderr, and an internal error exits 2, never 1. The one
    error record it writes is the exit-2 message in ConstrainedLanguage mode, which has no other
    route to stderr.

## Command line (identical for ps1, sh and go; the cmd launcher checks, then forwards)

```
--deep            enable tier "deep"
--net             enable tier "net"
--out DIR         parent directory for the output folder
--only IDS        comma-separated probe ids or area wildcards (net.*); others are skipped
--skip IDS        comma-separated probe ids or area wildcards to skip
--timeout SEC     per external command (default 15)
--budget SEC      whole scan (default 600); remaining probes become skipped
--no-redact       write secrets unredacted
--list-probes     print every probe with tier, title and footprint, then exit 0 (format below)
--version         print "envscan <version> (<impl>)" and exit 0
--help            usage, exit 0
```
Single-dash forms (`-deep`) are accepted too. Unknown arguments: usage on stderr, exit 2.
- Boolean flags take no value: `--net=false` or `--deep=0` exits 2 with "option --net takes no
  value", never silently enabling the flag.
- `--only`/`--skip` patterns may contain letters, digits, `.`, `_`, `-` and `*`. Each must match at
  least one probe id; otherwise exit 2 (a typo must not silently scan nothing). An empty list
  (`--only ""`, `--only=,`) exits 2 with "--only needs probe ids". The messages are
  "--only: invalid pattern 'x' (allowed: letters, digits, . _ - *)" and
  "--only: pattern 'x' matches no probe" (`--skip:` for skip).
- `--timeout`/`--budget` take 1-9 digits.
- `envscan.cmd` checks every argument before anything starts: before `--help`, the 32-bit
  relaunch, PowerShell or the fallback. It then forwards rebuilt, quoted values, never `%*`.
  It refuses with exit 2:
  - an empty argument, a quote character inside an argument, or an argument it cannot read;
  - an `--out` value with `%`, `<`, `>`, `|`, `*` or `?`, or, with `--wsh`, one that starts
    with `//` (cscript.exe takes such an argument as its own option). Every `--out` is forwarded,
    so each one is checked as it is parsed (`__ES_OUT_SLASH`), whatever the order of `--wsh`;
  - the same option and pattern errors as the scripts.

## Output

Folder `envscan-<hostname>-<UTC yyyymmddThhmmssZ>/` under `--out`, else the current directory
if writable, else home, else temp. Contents:

| File | Content |
|---|---|
| `envscan.json` | the report (schema `schema/envscan.schema.json`), pure ASCII, `\uXXXX` escapes |
| `envscan.md` | full human-readable report, one section per probe |
| `AGENT_BRIEF.md` | at most ~150 lines, written for a coding agent (layout below) |
| `envscan.log` | progress, per-probe timing, errors |

stdout receives exactly one line: the output folder path. Progress and error messages go to
stderr. The ps1 in ConstrainedLanguage mode cannot call the console streams. There it writes
progress with `Write-Host` only when stdout is a console, and otherwise leaves it out
(`envscan.log` keeps the per-probe timing); its exit-2 messages go through
`Write-Error -ErrorAction Continue`. Exit code: 0 all probes ok/not_found/not_applicable/skipped-by-tier;
1 any probe partial/denied/timeout/error or skipped by budget; 2 fatal (bad arguments, cannot
write output).

### Probe envelope (`probes.<id>`)

```json
{ "status": "ok", "tier": "default", "scope": "machine", "title": "...",
  "sources": ["uname -a", "read /etc/os-release"], "duration_ms": 12,
  "data": { }, "raw": { "label": "text" }, "truncated": false, "error": null, "notes": [] }
```
`raw` holds verbatim (redacted) command output keyed by a short label; cap 64 KB per probe and
set `truncated`. Omit `raw`/`notes` when empty.

### `host` block
`os_family` (windows, linux, darwin, freebsd, openbsd, netbsd, aix, sunos, hpux, cygwin, zos, os400, other),
`os_name` (pretty name), `os_version`, `arch` (normalized: x86_64, x86, arm64, arm, ppc64,
ppc64le, s390x, riscv64, sparc64, ...), `hostname`.

### Findings
`findings[]` items: `id`, `severity`, `title`, `recommendation` (all from `spec/findings.toml`),
`detail` (dynamic, one line), `evidence` (probe ids). Order: blockers, warnings, info.

## Data shapes (shared field names)

Implementations may add fields, but must use these names when the concept applies. Units are in
the name (`_mb`, `_kb`, `_bytes`, `_seconds`, `_ms`). Unknown values are `null`, not omitted.

| Probe | `data` fields |
|---|---|
| os.identity | family, name, version, build, edition, kernel, arch, process_arch, userland_bits, hostname, fqdn, domain, domain_joined, directory_joined, install_type, distro_id, distro_like, wsl, rosetta |
| os.time_locale | timezone, utc_offset, locale, encoding, utf8_available, decimal_separator, date_format, codepage_ansi, codepage_oem, codepage_console |
| os.health | uptime_seconds, last_boot_utc, load (array), pending_reboot (bool or null), pending_reasons (array) |
| os.updates | count, hotfixes [{id, installed_on}] |
| hw.cpu | model, vendor, cores, logical, sockets, features {sse4_2, avx, avx2, avx512f, aes, neon}, flags (array, Unix) |
| hw.memory | total_mb, available_mb, swap_total_mb, swap_free_mb |
| hw.storage | volumes [{mount, device, fstype, total_mb, free_mb, network, removable}] |
| hw.gpu | gpus [{name, driver_version, vram_mb}] |
| limits.process | nofile_soft, nofile_hard, nproc_soft, nproc_hard, stack_kb_soft, core_soft, memlock_kb_soft, address_space_soft (numbers or "unlimited") |
| limits.kernel | object keyed by sysctl name ("fs.inotify.max_user_watches": 8192, ...), plus systemd_default_limits |
| limits.cgroup | version (1, 2 or null), path, memory_max_bytes, cpu_quota_cores, pids_max |
| net.ports | ephemeral {start, end}, excluded_tcp [{start, end}], unprivileged_port_start, urlacl_count |
| user.identity | name, domain, uid, gid, sid, groups (array), is_admin (bool or null), elevation_method, integrity, home, shell, passwd_entry |
| user.profile | home, home_network, profile_type, redirected_folders {name: path}, onedrive, fslogix |
| env.vars | process {NAME: value}, machine {...}, user {...}, redacted (count) |
| env.path | separator, entries [{path, scope, exists, writable, network, duplicate, relative}] |
| shell.info | current_shell, shell_version, language_mode, execution_policy {scope: policy}, effective_policy, powershell_installed (array), sh_target, umask, shells (array), cmd_autorun, cmd_disabled, wsh_enabled |
| shell.userland | sed, awk, grep, tar, date, find (each gnu, bsd, busybox, other or null), perl |
| sec.app_control | applocker {configured, collections {Exe: Enforced/AuditOnly}}, srp, wdac {umci, kmci, vbs, services_running}, smart_app_control, exploit_protection, selinux, apparmor, fapolicyd, seccomp, no_new_privs, cap_eff, lockdown, sip, gatekeeper, mdm_enrolled |
| sec.crypto | fips (bool or null), schannel {...}, dotnet_strong_crypto {...}, crypto_policy, openssl_dir |
| tls.trust | roots [{subject, thumbprint, not_after, store, origin}], enterprise_roots (array of subjects), root_count, authroot_count, root_auto_update (bool or null), bundles [{path, certs}], custom_anchors (array), runtime_trust {VAR: value} |
| pkg.sources | configs [{id, tool, path, scope, lines (array), truncated, urls (array), proxy_urls (array)}], config_count, env {NAME: value}, git_config [{origin, key, value}], endpoints (array of `scheme://host[:port]`, taken from the raw values before redaction; no path or userinfo; net-never hosts and loopback dropped), proxy_urls [{tool, url, source}] |
| pkg.caches | caches [{id, tool, path, entries, truncated}] (existing caches only) |
| pkg.installed | managers [{name, count}], packages [{name, version, source}] (capped), truncated |
| tools.inventory | tools {id: {name, cat, found, path, paths (array), on_path, version, executed, reason, binary_arch}}, found_count |
| runtime.version_managers | managers [{id, name, shim_dirs (array), versions (array)}] |
| runtime.java | java_home, jdks [{path, version, vendor, arch, source}] |
| runtime.dotnet | framework {release, version}, sdks (array), runtimes (array) |
| runtime.python | interpreters [{path, version, store_alias}], launcher (array) |
| native.deps | libc {kind, version}, glibcxx_max, libssl (array), vcredist (array), ucrt, webview2, odbc_drivers (array) |
| net.interfaces | interfaces [{name, description, addresses (array), mac, mtu, gateways (array), dns (array), dhcp}] |
| net.routes | default_gateways (array), routes (array of strings) |
| net.dns | servers (array), search (array), hosts_entries (array), resolver_order |
| net.proxy | env {NAME: value}, winhttp {proxy, exclusions, direct}, wininet {enabled, server, exclusions, pac_url, auto_detect}, system {...}, package_managers [{tool, setting, value, file}] (proxy settings found by name: `setting` is the key, `value` redacted; GOPROXY/GONOPROXY are mirrors, not proxies; exclusion keys such as no_proxy, nonProxyHosts and no_proxies_on are not proxies; Ruby `:http_proxy:` counts) |
| net.listening | tcp [{address, port, pid, process}] |
| net.firewall | profiles [{name, enabled}] or {ufw, firewalld, macos_alf} |
| net.reachability | targets [{host, port, source, resolved (array), tcp ("ok", "refused", "timeout", "error", "unresolved", "skipped"), ms, error, reason}]. A skipped target (public host, net-never host, or a name that resolves to a net-never address) has `reason` and no resolved/ms/error, and adds a note without changing the status. The cap of 20 counts only targets that were looked up. |
| fs.mounts | mounts [{device, mount, fstype, options (array)}], key_paths {path: {mount, fstype, noexec, nosuid, ro}} |
| fs.locations | locations [{id, path, exists, writable, free_mb, fstype, noexec, network}] |
| fs.semantics | case_sensitive, symlink ("ok", "denied", "error"), hardlink, junction, long_paths_enabled, short_names, name_max, path_max |
| fs.exec_test | results [{id, path, kind, outcome ("ok", "blocked", "error"), detail}] |
| proc.list | count, processes [{pid, ppid, name, user, path, cmdline}] (capped), truncated |
| svc.list | manager, count, services [{name, display, state, start_mode, account, path}] (capped), truncated |
| sched.tasks | count, tasks [{name, path, state}], user_crontab (array), timers (array), linger |
| virt.platform | virtualization (none, vm, container, wsl, unknown), hypervisor, vendor, model, container {detected, engine, kubernetes}, wsl_distros (array), docker_socket {path, accessible}, kvm |
| session.context | type (console, rdp, ssh, service, unknown), interactive, display, terminal, tty, session_id |

## AGENT_BRIEF.md layout (identical headings in every implementation)

```
# Environment brief: <hostname>
_envscan <version> (<impl>) - <started_utc> - tiers: <tiers> - <n> probes: <ok> ok, <m> not fully checked_

## Platform
## Runtimes and tools
## Package sources and caches
## Blockers and warnings
## Where you can write and execute
## Network, proxy and TLS
## Limits
## Not checked
```
"Not checked" lists every probe whose status is not ok/not_found/not_applicable, with its
status and note, so a reader never mistakes "unknown" for "absent".

## Progress and --list-probes formats

```
envscan 1.0.0 (posix-sh): 44 probes, tiers default -> /home/u/envscan-host-20261111T101500Z
[ 1/44] os.identity ...................... ok        12 ms
```
`--list-probes` prints, for each probe the implementation provides (`spec.probes_for(impl)`), in
catalog order and with no header or trailing line:
```
<id>  [<tier>]  <title>
    - <footprint line>
```
One `    - ` line per footprint line of that implementation. ps1, sh, cmd and go print exactly this;
`tests/conftest.py` `expected_probe_listing` builds the expected text and each implementation's
test compares the whole output. `--version` is the only place that names the implementation.

## Portability checklist

### PowerShell (`src/ps`, enforced by `tools/target_ps.py` lint)
* PS 2.0 syntax and .NET 2.0 APIs only: no `[ordered]`, `[pscustomobject]`, `::new`, classes,
  `.ForEach/.Where`, `-in/-notin`, `$PSItem`, member enumeration (`$list.Name`),
  `-ErrorAction Ignore`, `Get-ChildItem -File`, `Get-Content -Raw`, `$PSScriptRoot`,
  `String.IsNullOrWhiteSpace`, `ConvertTo/From-Json`. Wrap results in `@()` before `.Count`.
* ConstrainedLanguage (verified on Windows 11, PS 5.1): method calls only on core types
  (`string`, `regex`, `datetime`, `char`...). These FAIL: `[IO.Path]::...()`, `[Math]::...()`,
  `[Convert]::...()`, `[BitConverter]`, `[Environment]::GetEnvironmentVariable()`,
  `New-Object` (ArrayList, StringBuilder...), `Start-Job`, `WindowsIdentity`, and
  `$_.Exception.GetType()` inside `catch` (use `.Message`, `.FullyQualifiedErrorId`).
  These WORK: static properties (`[Environment]::Is64BitProcess`, `[Console]::OutputEncoding`),
  `[regex]::Replace/Escape/Matches`, `[string]::Join`, `[DateTime]::UtcNow`, `[int]'0x1f'`,
  `[char]` casts, `-f`, CIM/WMI cmdlets, registry and `Cert:` providers, `Start-Process` with
  `.Handle`/`Wait-Process`/`ExitCode`, `Get-Content -Encoding Byte`, `Out-File/Set-Content`.
* Registry value names: `(Get-Item -LiteralPath $key).Property`; values via `Get-ItemProperty`.
* Every CIM/WMI call goes through the core wrapper (lint rules `cim-cmdlet`/`wmi-cmdlet`);
  binary reads through the core byte reader (`byte-encoding`); `Start-Job` only in the PS 2.0
  WMI path. Mark the single allowed line with `# lint-allow: <rule>`.
* The script must not contain PowerShell's suspicious-content keywords (see `SUSPICIOUS` in
  `tools/target_ps.py`, case-insensitive substrings), including in comments and spec text:
  e.g. the plural of "property", "Emit", "Bypass", "IntPtr", "Marshal", "Cryptography".
* `$env:` changes leak into an interactive caller's session. The process environment is set to
  exactly the child table (allowlisted snapshot variables, `[child_env]`, the call's extras) just
  around each `Start-Process` (and the PS 2.0 `Start-Job`), and restored right after; the process
  handle is taken before the restore. ProcessStartInfo is not an option (New-Object is refused in
  ConstrainedLanguage; `Start-Process -Environment` needs PS 7.4).
* Never format or parse dates with a format string. `ToString('yyyy...')` and `ParseExact` use
  the culture's calendar: a th-TH host would get Buddhist-era years. Use `Format-EsUtc` and
  `Format-EsStamp`, which build the string from the numeric fields, and `[datetime]` casts,
  which use the invariant culture.
* PowerShell hashtables are case-insensitive. Keys that differ only by case collide; this also
  applies to test harness case names.
* A hashtable entry named `Keys`, `Count` or `Values` hides the member of the same name. Data
  tables keyed by system values (registry names, variable names) use `.PSBase.Keys` and
  `.PSBase.Count`.
* Anchor validation regexes with `\A` and `\z`, never `^`/`$`: `$` also matches before a final
  newline, so `'^[0-9]+$'` accepts `"5`n"`.
* PS 2.0 has no `-Encoding Oem` (`Read-EsOemText` decodes with the OEM code page from the
  registry). It also has no `Get-Acl -LiteralPath`, and `Get-Acl -Path` fails on names with `[`
  or `]`, escaped or not (also on 5.1), so `Get-EsAclSddl` uses
  `(Get-Item -LiteralPath).GetAccessControl()` there.
* Batch files (`.cmd`/`.bat`) run as System32 `cmd.exe /d /v:off /s /c ""<path>" <args>"`
  (`Get-EsLaunch`); arguments containing `% & | < > ^` or a line break are refused.
* Module map:
  - `10-core.ps1`: JSON, progress and `Write-EsFatal`.
  - `11-exec.ps1`: child processes, timeouts and tree kill, the CIM cache, registry readers;
    the path guards `Test-EsLocalPath`, `Test-EsCredentialPath`, `Test-EsDeviceName`,
    `Get-EsLinkReason` and `Expand-EsPathPattern`; `Read-EsTextFile` and `Add-EsReadNote`.
  - `12-runner.ps1`: arguments and the probe runner.
  - `11-child-env.ps1`: the child environment (allowlist, path vetting, set/verify/restore around each child).
  - `14-redact.ps1`: the redaction rules; `14-redact-xml.ps1`: the xml LINE and TEXT rules.
  - `15-proxy.ps1`: a port of `src/sh/awk/proxy.awk`; keep the two in step
    (`tests/proxy_cases.py` runs against both).
  - `23-git-config.ps1`: git configuration, includes and the network-home replacement. A
    failing `git config` run makes the probe `partial` with "git config: exit code N: <first
    stderr line>".
  - `2x-probes-*.ps1`: the probes. `30-findings.ps1`, `40-render.ps1` and `41-brief.ps1`: the
    findings and the outputs.

### POSIX sh (`src/sh`, enforced by `tools/target_sh.py` lint)
* POSIX only: no `local`, `[[`, `function`, `source`, arrays, `${var:off}`, `${var/x/y}`,
  `$RANDOM`, `echo` (use `printf '%s\n'`), `which`/`command -v` (use the own PATH resolver),
  `mktemp` (mkdir with umask 077), `date +%s` (awk `srand()`), `hostname` (`uname -n`),
  `readlink -f`, `stat`, `seq`, `sed -E/-i`, `grep -o/-a/-P/-r`, `head -c`, `find -maxdepth`.
* No here-document body larger than 3000 bytes: MSYS/Cygwin dash silently drops larger ones
  (the generator splits spec tables; awk programs go in single-quoted arguments).
* Text processing under `LC_ALL=C`; JSON escaping in awk without backslash `gsub` replacements.
* The preamble repairs CRLF line endings and re-execs into a POSIX shell on pre-POSIX `/bin/sh`.
* Never stat NFS/autofs mounts (`df -P -l`, read `/proc/mounts`); `getent passwd "$(id -u)"` only.
  A mount type is a network mount when it is in `spec/policy.toml` `network_fs`, or starts with a
  `network_fs_prefixes` entry (`fuse.`) and is not in `local_fuse` (lxcfs, fuse-overlayfs,
  snapfuse, ...): an unknown FUSE file system is treated as network (fail closed).
* Paths from the environment, HOME, a glob or a link are tested only through `es_ltest OP PATH`
  (checks the mount table first, following links; a refused path goes to `ES_NETSKIP` and the
  probe notes it). Executables are tested only through `es_exec_file`, which vets a link's
  target before any `-f`/`-x`. Globs go through `es_glob`, which runs `es_cred_path` on the
  pattern first and vets every result. Never write `[ -d "$JAVA_HOME" ]` or a bare
  `for f in $HOME/x/*` loop.
* Module map:
  - `11-policy.sh`: what may be executed (shim directories, network mounts) and `es_cred_path`,
    built on the matchers and `ES_NET_FS` generated from `spec/policy.toml` (case-insensitive
    patterns, so `~/.SSH` is `~/.ssh` on macOS).
  - `12-mounts.sh`: the mount table, read before the temp folder is created where
    `/proc/self/mounts` exists, so a TMPDIR or HOME on a network mount is never used.
  - `13-child.sh`: `es_child`, the body of every `es_exec` child. `es_child_keep_init` (scan
    start) picks the `[child_env_keep]` names present in the environment (via awk `ENVIRON`, names
    checked against `[A-Za-z_][A-Za-z0-9_]*`); each child then starts through
    `env -i NAME=value ... cmd` with, one entry per name: the probe's extras (`ES_CHILD_EXTRA`, a
    list of `NAME` or `NAME=SRC` entries, SRC being the scanner variable that holds the value, so git's
    replacement HOME/XDG_CONFIG_HOME/GIT_CONFIG_* and fc-list's XDG_CACHE_HOME reach the child only
    and the scanner's own values never change),
    `LC_ALL`, `DOCKER_CONTEXT`, the `[child_env]` overrides, then the kept variables. Without an
    `env` command the child subshell unsets every other exported variable instead. Utilities the
    shell runs itself for its own parsing (awk, tr, od, ls, ps, uname, date, the z/OS iconv) are
    not `es_exec` children and keep the scanner's environment; they are system tools that read
    no tokens. The pid wrapper (`$ES_SH -c`) starts after `env -i`, never with the full environment.
    Allowlisted values appear in env's argv (visible to `ps`); none of them is secret.
  - `13-childvet.sh`: path vetting of the kept variables (`home_paths`, `path_lists`, other absolute
    paths), cached per value at scan start and re-checked when a probe changes a value.
  - `14-netfs.sh`: the network-mount rule (`es_is_netfs`, the awk twin `es_isnet`, `es_net_fs_extend`).
    `/proc/*/mounts` escapes are decoded (`\ooo`), except tab and newline, which stay `\011`/`\012`;
    paths are compared in that same spelling (`es_mount_text`).
  - `24-git.sh`: git configuration, includes and the network-home replacement.
  - `28-reach.sh`: `--net` reachability.
  - `awk/redact.awk`: the redaction rules (names, values, command lines); `awk/redact_xml.awk`: the
    xml LINE rule and the xml parts of the TEXT RULES (linear: each line is split once on "<");
    `awk/redact_text.awk`: the other TEXT RULES (blocks, multi-line values). `es_awk_program` joins
    redact, redact_xml, redact_text and json.
  - `awk/json.awk`: JSON, Markdown and config-line output.
  - `awk/proxy.awk`: proxies found by setting name, never by "proxy" in a value. It is ported
    to `src/ps/15-proxy.ps1`; change both together.
  The awk programs are embedded with `es_awk_program`; `proxy.awk` is written to
  `$ES_TMP/proxy.awk` by `es_init`.
* Helpers return results in their own variables (`es_normdir` sets `ES_ND`). Helpers must not
  overwrite `ES_T`, which callers keep across calls.
* Environment variable names and values are read through awk `ENVIRON` and kept in memory only;
  the unredacted environment is never written to disk.
* Raw intermediate files are registered in `ES_RAW_FILES` and removed by `es_raw_drop` as soon
  as their probe ends. EXIT, INT, TERM, HUP, QUIT and PIPE run `es_cleanup`, which removes
  `$ES_TMP` (mode 0700). Known residual risk: probe events are redacted when the report is
  rendered, so until then unredacted probe data sits in `$ES_TMP`, and a SIGKILL leaves it
  behind. The same applies to decoded copies of UTF-16 files (`$ES_TMP/dec.<probe>.<n>`, made by
  `es_text_prep`); a file with a BOM or NUL bytes that cannot be decoded safely is never emitted
  (the probe is partial: "UTF-16 or binary content not read"). Without `/proc/self/mounts` (macOS, BSD, AIX, Solaris), a TMPDIR on a network mount
  is only logged after the fact.
* Only gawk (`--posix`) and MSYS awk are tested here; mawk, nawk and busybox awk are checked
  by reading. Avoid gawk-only features (`length(array)`, `{n}` intervals, `\s`, `nextfile`,
  `IGNORECASE`).
* **z/OS UNIX and IBM i (tier 2, best effort, unverified).** `uname -s` "OS/390" is os_family
  `zos` (arch s390x), "OS400" is `os400` (ppc64). Both were written from IBM's documentation;
  no test system existed. The rules that keep them from breaking the other systems:
  - **No ASCII letter ranges** (`A-Z`, `a-z`) in `src/sh`: in EBCDIC they also contain `} \ ~`
    and accented letters. Spell the letters out in bracket expressions and `tr` (no
    `[[:alnum:]]`: mawk 1.3.3 lacks it). `tests/test_sh_letter_ranges.py` lints this. Digit
    ranges and `A-F` are contiguous in EBCDIC and stay.
  - **EBCDIC mode.** `es_detect_ebcdic` (`printf A | od -An -tx1` gives `c1`) sets `ES_EBCDIC`;
    `es_awk` then passes `-v ebcdic=1 -v ebcdic_tab=<IBM-1047 table>`. `json.awk` learns the 95
    printable ASCII characters from a string literal (right in any EBCDIC code page), maps every
    other byte through the table (`spec/ebcdic.toml`, generated once from Python's cp1047 codec
    by `tools/gen_ebcdic.py`, validated in `tools/spec.py`) to `\uXXXX`, and skips UTF-8
    validation. awk variable names of `redact.awk` and `json.awk` share one namespace (a
    collision with `NPRE` once broke EBCDIC mode: check before adding globals).
  - **Output conversion** is `es_ebcdic_convert` (`40-render.sh`), after the four files are
    written: `iconv -f IBM-1047 -t UTF-8` into a file below `$ES_TMP`, a self-check
    (`es_conv_check`: LF bytes present, no C2 85 pair, `envscan.json` starts with `{`; z/OS iconv may
    keep NL as U+0085), `mv`, `chtag -tc 1208`, all run without the auto-conversion settings. It
    only runs when `printf [` is byte `ad` (IBM-1047); the awk table is 1047-only, so in another
    EBCDIC page non-printable bytes become U+FFFD (JSON) or `?` (Markdown). Any failure leaves the
    EBCDIC text and logs; the report is never lost. The table maps 0x15 to U+000A (the z/OS UNIX NL
    is LF); that only matters for JSON escapes, never for the converted files.
  - **Identity and environment.** z/OS release and version come from `uname -Ia` (plain
    `uname -r/-v` are OS/390-compatible; `uname -p` is never run there; fallback is partial with a
    note). The preamble keeps the user's `_CEE_RUNOPTS` and `_BPXK_AUTOCVT` (`ES_PRE_*`) and
    `env.vars` reports those, with a note.
  - **Fail closed on mounts.** On z/OS and IBM i only `zfs hfs tfs` / `udfs qsys root ...` count as
    local (`es_local_fs_list`); every other type, `unknown` and `nfs3` included, is a network mount.
    `es_netmnts_early` lists `/QNTC` and `/QFileSvr.400` before the temp directory is made; the
    `df` fallback skips mounts under network roots.
  - **Preamble.** The CRLF repair and the POSIX re-exec only `exec` a shell that exists (IBM i
    has no `/bin/sh`; candidates include `/QOpenSys/usr/bin/sh`, `/QOpenSys/pkgs/bin/bash`).
    `OS/390` exports `_BPXK_AUTOCVT=ON` and APPENDS `FILETAG(AUTOCVT,AUTOTAG) POSIX(ON)` to
    `_CEE_RUNOPTS`, never replacing it. `OS400` puts `/QOpenSys/usr/bin:/QOpenSys/usr/sbin`
    first in PATH; a shell that does not print `41` for `printf A | od` (QSH, or no `od`) is
    re-executed through `/QOpenSys/usr/bin/sh` once (`ENVSCAN_QSH`), else exit 2 "run
    envscan.sh from PASE".
  - **Network paths.** `/QNTC` and `/QFileSvr.400` are always network roots (`es_os_netmnts`);
    `nfs3`, `automnt`, `dfs`, `qntc` and `qfilesvr*` count as network file system types. On z/OS
    `hw.storage` never runs a plain `df` (it also asks NFS servers): only `df -P -k` on mount
    points whose type the mount table shows as local.
  - **Deep tier on IBM i** (`user.privileges`): display-only `system "DSPSYSVAL SYSVAL(...)"`
    for QSECURITY, QCCSID, QTIMZON, QLANGID, kept as raw text, not parsed.
  - The test stubs and fixtures (`tests/stubs/{zos,os400}`, `tests/fixtures/{zos,os400}`) are
    hand-written from the documentation. Replace them with captured output when a real system
    is available, and move the platforms out of tier 2 only then.

### JScript (`src/js/NN-*.js`, enforced by `tools/target_js.py`)

`envscan.js` is a port of `envscan.ps1` for Windows Script Host: `cscript //nologo //E:jscript
envscan.js`, JScript 5.8 (ES3). It is started by `envscan.cmd --wsh` (see the cmd section) or by
hand, never by `wscript.exe`.
* **Naming contract.** Every PowerShell function `Verb-EsNoun` is the JScript function `verbEsNoun`
  with the same parameters (a `[switch]` is a trailing boolean) and the same return shape; probes keep
  `probe_<area>_<name>`; `$script:ES_X` is the global `ES_X`. JScript-only helpers carry a file prefix
  (`jsGit_`, `jsNet_`, ...). A change to a ps function must be mirrored in its JScript twin.
* **Modules.** `00-header` (ES_FSO, ES_SHELL: the only COM instances besides the WMI locator), the
  generated spec block, `10-core` (state, utilities, environment, log, JSON writer), `11a`-`11e`
  (commands, WMI worker, registry, path guards, files), `12-runner`, `13-helpers*`, `14-redact*`,
  `15-proxy`, `20`-`26` probes, `30-findings*`, `40-render`, `41-brief*`, `90-main`, `99-entry`.
  The lib (`build/lib/envscan-lib.js`) leaves out `9x-*`.
* **Lint.** ES3 only (no let/const, arrows, template strings, JSON, Array forEach/map/filter/indexOf,
  trim, Object.keys, Date.now, bind), no trailing comma in literals (JScript counts an extra element),
  no `eval`/`Function`/`GetObject`/`execScript`, `new ActiveXObject` only with a literal ProgID from
  `Scripting.FileSystemObject`, `WScript.Shell`, `WbemScripting.SWbemLocator`, ASCII, CRLF, and the
  same suspicious-keyword list as the ps1 (AMSI scans WSH too). The one exception is StdRegProv's
  in-parameters, `.Methods_.Item(`, on lines marked `// lint-allow: wmi-inparams`.
  The rules run on the whole text (a call split over lines is still caught). Also rejected:
  `CreateObject`/`GetObject` on any receiver, `.constructor`, `setTimeout`/`setInterval`, `.Run(`,
  `.Popup(`, `.LogEvent(`, `.SendKeys(`, `.ShellExecute(`, `.RegWrite(`/`.RegDelete(`, `Environment(...)`
  other than `"PROCESS"`, `ConnectServer` to anything but `"."`, string indexes that name or build a
  banned member, and any member of `ES_FSO`, `ES_SHELL` or `WScript` outside `MEMBER_ALLOWLIST`
  (aliasing them is an error too). `ActiveXObject` occurrences are counted per file against literal
  allowlisted ProgIDs. `this`/`ES_GLOBAL` need `// lint-allow: global-lookup` (only the probe lookup,
  which first checks `^probe_[a-z0-9_]+$`); delete/copy/move calls need `// lint-allow: temp-cleanup`.
  `.hasOwnProperty(` is allowed only as `Object.prototype.hasOwnProperty.call(`; code uses `esHas(obj,
  key)`, so a data key named `hasOwnProperty` cannot break a probe.
* **JScript traps the lint cannot see.** `s[i]` on a string is `undefined` (use `charAt`); `split` with a
  regex drops empty fields; regexes have no lookbehind, `\A`/`\z` or inline flags, and `\s` differs from
  .NET (the redaction ports rewrite it to the .NET set, U+00A0 included); PowerShell comparisons and
  hashtables are case-insensitive, JScript's are not; `for in` lists numeric keys first.
* **cscript exit codes.** A runtime error or a `//T` timeout exits 0, a syntax error 1. So
  `envscan.js` exits 100 + its code when `__ES_EXIT_BASE` is exactly `100` (set by `envscan.cmd` for
  that child only; removed from the environment before any child starts), and the launcher treats every
  other code as "WSH failed".
* **Trusted Windows folder.** `SystemRoot`, `windir` and `SystemDrive` are never trusted for executables or
  the child cwd: the Windows folder is `ES_FSO.GetSpecialFolder(0)` (ps1: the parent of
  `[Environment]::SystemDirectory`, a static property that works in ConstrainedLanguage and PS 2.0) and
  must pass `testEsSystemFolder` (a plain local `X:\name` path, no UNC, mapped drive, `%`, `~`,
  wildcard, link or credential store). Without it no command runs and the temp folder is refused.
* **Commands** run as `<Windows>\System32\cmd.exe /d /v:off /s /c ">out 2>err <stdin.empty "prog"
  args"` from `WScript.Shell.Exec`, cwd the Windows folder's drive root, the `spec/child_env.toml` environment
  (`esStartChild` with `src/js/11f-childenv.js`: every process variable that is not in
  `[child_env_keep]`, `ES_CHILD_ENV` or the call's extras is removed just before Exec, kept path
  values are vetted (UNC, mapped network drive, credential store: home paths replaced, list entries
  dropped, others removed), the environment is listed again and the command is not run (restore +
  error) if anything else is left or a removal failed; everything is put back exactly, empty values
  included, in a `finally` right after Exec; names starting with "=" are never touched),
  polled with a timeout; on timeout the process tree is stopped (Win32_Process snapshot, WMI
  Terminate). Program paths must be absolute; arguments with `%`, `"`, CR, LF or NUL are refused (cmd
  expands `%` even inside quotes); arguments with white space or `& | < > ^` are double-quoted. The
  recorded `command` text is the ps1 form, so sources match.
* **WMI worker.** CIM queries run in `cscript //T:<timeout> envscan.js --es-wmi-worker <req> <res>`, so a
  hung provider cannot hang the scan. `getEsCimSafe(class, ns, filter, props)` needs the property list
  (`SELECT props FROM class`), `Prop.Sub` reads one level of embedded objects; unsigned and 64-bit
  values are fixed from the class MOF. The worker accepts only request and result paths inside an
  `%TEMP%\envscan-N-N` folder holding `stdin.empty`, and never starts a worker itself
  (`__ES_WMI_WORKER`). A test snippet that uses CIM starts with `esInitForTests(<dist envscan.js>)`
  (`tests/js_harness.py js_init_snippet`): without it every worker re-runs the snippet and starts another
  worker. `run_js` sets `__ES_TEST_TEMP_REPORT=1` so the snippet's temp folder is reported on stderr and
  removed afterwards, even after a timeout. The worker re-checks its request: a namespace matching
  `ES_WMI_NAMESPACE_RE`, `SELECT <props> FROM <class> [WHERE ...]` only (no ASSOCIATORS/REFERENCES),
  numeric PIDs, and a tree-stop only for a process whose CreationDate lies in the window the parent
  recorded around its start (a recycled PID is never stopped).
* **Credential stores in the path guards.** `getEsRefusedFolder` (ps1 `Get-EsRefusedFolder`) returns
  "credential store" for a path that is or lies below one, before any file system access, so every
  reader, lister and output or candidate check inherits it. A final path component that is an 8.3
  short name (`RUNNER~1`) counts as a possible store. Mapped drives are read before the temp folder is
  created, and a TEMP on a network drive or in a store is refused.
* **Registry.** StdRegProv lists keys and values (64-bit view); `WScript.Shell.RegRead` reads values
  (StdRegProv would expand REG_EXPAND_SZ with the WMI host's profile). `getEsRegBinary` returns every
  byte; `getEsRegValue` caps binary values at 256 bytes as hex. Registry reads cost 5-19 ms, so a scan
  takes about three minutes.
* **Files.** FSO only. Bytes are read exactly through FSO's Unicode mode (each UTF-16 unit is two bytes);
  text is decoded as UTF-16 (BOM), UTF-8 (BOM or strict), else ANSI. Every reparse point (symlink,
  junction, cloud file, app alias) is a link with an unknown target and is never followed: FSO cannot read
  a link target, and `dir /AL` would be a new command. Nothing inside such a folder is listed or tested
  (its target could be a credential store): a PATH folder that is a link goes to `ES_PATH_LINK_DIRS`,
  and the probes that use the PATH index note it and are partial, so a tool there is "not checked",
  never "not found".
* **No token or ACL API.** `getEsTokenInfo` gives the profile SID from ProfileList and an assumed
  standard-user group list (`groups_source` "assumed", `is_admin` null); `getEsSddlAccess` returns
  `null` rights. Probes report those facts as unknown (partial), and never add `whoami`, `icacls` or
  test writes to the default tier for them.
* **Output.** `envscan.json` is pure ASCII; the Markdown files and the log are written as ASCII with
  `?` for other characters (FSO cannot write UTF-8 portably). `net.reachability` contacts nothing: it
  lists the targets with the ps1 skip reasons and is `not_applicable`. `ES_LANGUAGE_MODE` is `WSH`.

### Go (`src/go`, enforced by `tools/target_go.py`)

The static binary `envscan-linux-<arch>` is a port of `envscan.sh` for Linux. Its sources are flat
package `main` in `src/go` (no subfolders), standard library only, `go 1.27` in `go.mod`. The
hard rules above apply to it. The build never writes into `src/go`.
* **Lint, before anything is built** (`lint_sources`). ASCII only. No cgo (`import "C"`), `unsafe`,
  `plugin`, `net/http`, `net/rpc`, `net/smtp`, `os/user` or `debug/buildinfo`. `net` and
  `crypto/tls` only in `reach*.go`; `os/exec` only in `exec*.go`; no `//go:linkname`.
* **Source ownership by file prefix.**
  - `api_`: the shared contract: the data model with its redaction kinds (string, Named, Line, Cmd,
    Text, Verbatim, NumText), Result, the `Env` interface every probe must use, the spec loader and
    the service variables. A change here changes every probe; review it as a contract.
  - `engine_`, `exec_`, `sys_`, `main.go`: the scan driver, options, output files, child processes
    and system calls.
  - `redact_`, `proxy_`: ports of `redact.awk` and `proxy.awk`. They run the shared redaction and
    proxy JSON cases.
  - `report_`: the findings, Markdown and brief ports.
  - `pa_`, `pb_`, `pc_`: the probes.
  - `reach_`: `net.reachability`.
  - `testenv_fake_test.go`: `fakeEnv` for the tests.
* **Probes touch the system only through `Env`.** All `Env` paths are logical: `ENVSCAN_ROOT` is
  added to them, except paths under `TempDir()`.
* **spec.json.** `stage()` writes `spec.json` into the build folder (`spec_doc`: the `go` probes and
  the Unix rows of the tools, configs, caches, findings and redaction tables, as sh gets them). The
  engine embeds it with `//go:embed spec.json`. Never write a copy by hand.
* **Build** (`build_all`). `go vet` runs for linux/amd64 and windows/amd64 first. Then each target
  (`linux/amd64`, `linux/arm64`, `linux/s390x`, `linux/ppc64le`) is built twice with
  `CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS= GOAMD64=v1 GOARM64=v8.0 GOPROXY=off` (also `GOSUMDB`,
  `GOWORK` and `GOTELEMETRY` off), `-trimpath -buildvcs=false -ldflags "-s -w -buildid="`. The two
  builds must be byte-identical; a difference fails the build. amd64 and arm64 are supported;
  s390x and ppc64le are built and checksummed but never run here.
* **Toolchain.** `ENVSCAN_GO` (the `go` binary or its GOROOT), else `%LOCALAPPDATA%\envscan-dev\go`,
  else PATH. It is needed only on the build machine, never on a target. Without it the release
  build stops with a message.
* **Staging for go test and go vet.** `python tools/target_go.py stage DEST [PREFIX...]` copies
  the sources and `spec.json` into DEST. With prefixes, only `api_*.go`, `go.mod`, `testenv_*.go`
  and the files whose names start with a prefix are copied.
* **Test-only Windows build.** It refuses to scan unless `ENVSCAN_ROOT` and `ENVSCAN_TEST_OS=linux`
  are set. `ENVSCAN_TEST_CMDS` (a JSON table of command outputs) exists only in the `!linux` builds.
  Release binaries have no test hook; `tests/test_go_scan.py` checks that.
* **Footprint.** `spec/footprint/go.toml` lists what each probe reads or runs. Its header also says
  what is shared at scan start and what the binary never runs (shims, `.ps1` files).

### cmd (`src/cmd/NN-*.cmd`, enforced by `tools/target_cmd.py`)

* **No `[child_env_keep]` allowlist here, on purpose.** The launcher and the fallback start only
  System32 tools through `%__ES_SYS%\` (reg, findstr, chcp, tzutil, whoami, ipconfig, route, netsh,
  mountvol, subst), the Sysnative relaunch of itself, and the scanners (PowerShell, cscript), which
  must see the full environment to report it. Listing the environment in cmd needs a
  `FOR /F ('set')` child (AutoRun) or an unredacted temp file, and names holding `! ^ % "` cannot be
  cleared reliably. `tests/test_cmd_build.py::test_only_system32_tools_and_the_scanners_run` fails
  as soon as any other program is started; that is when this decision must be revisited.
* The parts are joined in name order; each starts with `rem ##` header lines that the build
  leaves out. Order matters: cmd searches the file for every `call` label, so the most-called
  routines sit next to their callers. Each part is CRLF, ASCII and ends with CRLF.
* CRLF line endings (the build enforces them), ASCII, `setlocal`, delayed expansion toggled so
  values containing `! & | < > %` survive; secret-looking variable values redacted.
* **No outside value in a `%expansion%`.** cmd expands `%VAR%` before it parses quotes, so a
  value containing `"` or `)` would run commands. Environment variables, registry values, file
  contents and command output are read with `!expansion!` and checked first:
  - `:es_env_path` rejects `" < > | * ?`;
  - `:es_env_word` keeps letters, digits and `. _ -`;
  - policy names must be one of the known names;
  - dates, times and code pages are reduced to digits.
  No outside value is passed to `call`, which expands `%` a second time.
  `tests/test_cmd_security.py` scans the source for violations and runs the fallback with hostile
  values in about 35 variables.
* System programs always run from System32 (`%__ES_SYS%\chcp.com`, never a bare `chcp`, which
  would find a planted `chcp.bat` in the current directory).
* Variable names starting with `__ES_` are reserved. The launcher's temporary files are
  `envscan-launch-<digits>.err` and the capture file `envscan-launch-<digits>.out`. They go in
  the user's own TEMP, TMP or LOCALAPPDATA\Temp, on local drives only, with the system drive
  preferred, and are deleted on every exit path. A fallback without a temp folder captures to
  `envscan-capture.tmp` in its output folder, and never captures the unredacted `set` list
  there.
* **No `FOR /F ('command')`, no pipes, no `%*`.**
  - `FOR /F` with a command starts a child cmd.exe, which runs the user's AutoRun.
  - In a pipe, a program that cannot start ends the whole batch with exit code 255.
  - Instead, run `"%__ES_SYS%\x.exe" ... <nul >"%__ES_CAP%" 2>nul`, then read the result with
    `for /f "usebackq ..." %%a in ("%__ES_CAP%")`. `FOR /F` reads the whole file before its
    first pass.
  - `FOR /F` children remain only in the `*_child` labels, which run when no capture file can
    exist (`tests/test_cmd_build.py` enforces this).
  - Arguments are read only through the REM capture (`rem #%1#` with echo on; REM ignores
    `& | < > ( )`), and then `:es_arg_ok`. A bad argument (`__ES_BADARG`) is reported before
    help, the relaunch and the launch.
  - PowerShell gets `__ES_FWD`; the relaunch gets `__ES_CMDARGS`.
* Before starting PowerShell (powershell.exe or pwsh.exe), the launcher sets
  `POWERSHELL_TELEMETRY_OPTOUT=1` and `POWERSHELL_UPDATECHECK=Off` for the child only. Without
  them, pwsh contacts Microsoft at startup, before the script runs.
* `:es_sysroot` accepts SystemRoot (else windir) only as `X:\` followed by letters, digits,
  `. _ - \` and with a `System32` folder; else `C:\Windows`. SystemDrive is kept only as a drive
  letter with a colon; else the drive of that Windows directory. The script's own children get
  `SystemRoot=%__ES_WIN%` from `:es_init`; PowerShell and cscript.exe, started after `endlocal`
  (which restores the caller's values), get `SystemRoot=%__ES_WIN%` and
  `SystemDrive=%__ES_SYSDRIVE%` on their launch lines.
* When TMP (or TEMP, if TMP is unset) would be longer than MAX_PATH (260), Windows hangs
  `FOR /F ('command')` and even PowerShell startup at full CPU. `:es_safe_tmp` therefore gives
  the script and its PowerShell a short TMP: the caller's TEMP, else `LOCALAPPDATA\Temp`, else
  `%SystemRoot%\Temp`. Known residual: the ps1 and sh child processes do not guard against this.
* cmd pitfalls:
  - In `delims=`, a space followed by other characters is a syntax error that silently ends the
    called label.
  - A program that is not found still truncates its `>` file.
  - REM prints its help when its line contains `/?`, even in a comment, so no REM line may
    contain it (`tests/test_cmd_build.py` checks). The argument capture uses this: when the
    capture holds no echoed `rem <n>#...#` line, the argument contained `/?` and is treated as
    a help request (usage, exit 0, nothing starts). Each capture line carries the argument's
    number, so a stale line cannot pass for the current argument.
* When reg.exe cannot read the registry at all (`CurrentBuild` fails), the policy prediction is
  "unknown". The launcher then never prints the Bypass line. It starts PowerShell anyway and
  falls back only on PowerShell's own refusal. The fallback header gets a `registry:` line, and
  registry values read "not read".
* Known residual risks, accepted:
  - Without any private temp folder, arguments are read with `%~1`, and the `*_child`
    `FOR /F` children (with AutoRun) run. When the only temp folder is on a non-system drive,
    `mountvol` and `subst` run that way before the capture file exists.
  - `--deep=` with an empty value cannot be told apart from `--deep`.
  - A registry value denied by a per-key ACL looks like a missing value.
  - The unredacted `set` list is in the private temp file until the first loop pass empties
    it. If cmd.exe is killed in that window, the file stays.
  - A bare `user:password@host` followed directly by a non-ASCII character is not recognised,
    so its password stays. This holds in every implementation. The one difference is the ps1,
    which treats a Unicode space such as NBSP as whitespace (`\s`).
* Spec data reaches the parts through placeholders filled in by `tools/target_cmd.py`, for
  example `@@ES_REDACT_TOOL_OPTIONS@@`, `@@ES_REDACT_TOOL_NAMES@@` and `@@ES_ALL_PROBE_IDS@@`.
* The fallback writes the sectioned text file `envscan-fallback.txt` and honours
  `--only`/`--skip`. Exit codes are 0 (complete), 1 (some probes partial) and 2 (bad arguments).
* `--wsh` (part `05-wsh.cmd`; launcher-only, never forwarded to PowerShell; saved across
  PowerShell in `__ES_SV_WSH`). Every `goto :es_fallback` taken because PowerShell cannot run
  goes through `:es_try_wsh` instead (`--fallback` goes straight to the fallback). It passes on
  to the fallback, with `__ES_WSH_WHY` set, unless all of these hold:
  - `--wsh` was given;
  - the reason (`:es_wsh_allowed`) is `missing`, `noscript`, or `policy`/`refused` without
    `__ES_POL_GPO` and `__ES_POL_UNREAD`. Never `blocked` (application control) or `failed`;
  - `:es_wsh_ready`: the capture and error files exist, `%__ES_SYS%\cscript.exe` (64-bit after
    the relaunch) and `%__ES_DIR%envscan.js` exist, and the Windows Script Host settings allow
    the script. HKLM, then HKCU unless HKLM `IgnoreUserSettings` is 1: `Enabled` 0 or a
    `TrustPolicy` other than 0 forbid it. `UseWINSAFER` is 1 by default, so instead of reading
    it the launcher looks for Software Restriction Policies (`Safer\CodeIdentifiers` with
    `DefaultLevel` or a rule subkey; Windows itself may create the key with only
    `authenticodeenabled`) and AppLocker script rules (`SrpV2\Script`): either forbids it.
    Unreadable registry forbids it.
  - `:es_wsh_ci` (called by `:es_wsh_ready` and `:es_guidance_wsh_hint`): App Control for
    Business (WDAC) and Smart App Control forbid it. WDAC: `System32\CodeIntegrity\SiPolicy.p7b`
    (also under `Sysnative` for a 32-bit cmd.exe), checked with `if exist` only, never opened,
    no FOR /F child. Smart App Control: HKLM `SYSTEM\CurrentControlSet\Control\CI\Policy`
    `VerifiedAndReputablePolicyState` present and not 0 (1 on, 2 evaluation), read with
    `:es_reg_get`. `CiPolicies\Active\*.cip` is deliberately not checked: stock Windows 11
    keeps inbox policies there (Smart App Control base policies, the driver block list) with
    nothing enforced, so any `*.cip` would refuse WSH everywhere. Not detectable: multiple-format
    WDAC policies (`*.cip`), a policy kept only on the EFI system partition, and whether
    `SiPolicy.p7b` actually restricts scripts (its presence alone refuses WSH).
  - `:es_wsh_launch` mirrors the PowerShell launch (endlocal, `:es_clear_inherited all`, `<nul`,
    the TMP fix) and runs `"%__ES_SYS%\cscript.exe" //nologo //E:jscript "%__ES_DIR%envscan.js"`
    with `__ES_JSFWD`: values quoted as in `__ES_CMDARGS`, because WSH does not read `\"` as a
    quote. `__ES_EXIT_BASE=100` is set for that child only. Never `//B` (it hides the error
    text), never `wscript.exe`. `:es_after_ps` has its own `setlocal`, so a launch after
    PowerShell's refusal also gives envscan.js the caller's environment. `__ES_JSFWD` holds
    quotes and cannot be carried in `__ES_SV_*`: `:es_restore` rebuilds it (`:es_wsh_args`)
    from the restored options.
  - `:es_after_wsh`: 100, 101 and 102 are envscan.js's results 0, 1 and 2 (stderr shown, no
    fallback); Ctrl+C is passed on as for PowerShell. Anything else means WSH failed (cscript.exe
    exits 0 after a runtime error or a `//T` timeout, 1 after a syntax error or when WSH is
    disabled): the fallback runs with a `wsh:` header line, cscript.exe's error output in the
    report, and a guidance line. No message text is read.
  - Without `--wsh`, `:es_guidance_wsh_hint` offers `envscan.cmd --wsh` only for `missing`,
    `noscript` and a local policy, and only when envscan.js and a capture file exist and
    `:es_wsh_ci` finds no WDAC policy and no Smart App Control.

## Testing

* `tests/test_build.py` - spec validation, generation, lint; the ps and sh footprints against the
  `probe_<area>_<name>` functions.
* `tests/test_registry_build.py` - the registry and the script/binary build split (a fake binary
  builder and registry are injected; nothing is downloaded or compiled).
* `tests/test_policy.py` - `spec/policy.toml` validation, generated data, case-insensitive matching.
* `tests/test_ps_*.py` - PowerShell, in FullLanguage and ConstrainedLanguage:
  - `test_ps_unit.py`: library cases from `tests/ps/unit_cases.ps1`;
  - `test_ps_redaction.py`: redaction cases;
  - `test_ps_scan.py`: whole scans;
  - `test_ps_unix_shim.py`: the Unix shim (stub sh; one real run through pwsh 7 and dash).
* `tests/test_sh_*.py` - sh under dash and `bash --posix`, with `ENVSCAN_ROOT` fixtures in
  `tests/fixtures/<name>/` and stub binaries in `tests/stubs/<name>/` that log invocations.
  `test_sh_ebcdic.py` (IBM-1047 table, json.awk EBCDIC mode, detection, conversion),
  `test_sh_preamble_zos.py` and `test_sh_zos_os400.py` (whole scans with a stub `uname`) cover
  z/OS and IBM i; a stub `uname` hides the Cygwin/MSYS host, so those scans pass `--out` and
  `ENVSCAN_ROOT` in POSIX form.
* `tests/test_go_*.py` - the Go binary, with the helpers in `tests/go_harness.py` (stages the
  sources; `run_dev()` sets `ENVSCAN_ROOT` and `ENVSCAN_TEST_OS=linux`; commands come from the JSON
  table named by `ENVSCAN_TEST_CMDS`, so no child process runs). They skip without a Go toolchain:
  - `test_go_engine.py`: the engine, options and files;
  - `test_go_redaction.py`: the redaction cases (shared JSON cases);
  - `test_go_report.py`: the findings, Markdown and brief;
  - `test_go_scan.py`: a fixture scan with the dev binary, the schema, nothing left behind, the
    secret canary, parity of the file-derived probe data with `envscan.sh` on
    `tests/fixtures/linux-basic`, and the release binaries (static ELF per architecture, no build
    paths, no test hook).
* `tests/test_cmd_*.py` - the cmd launcher and fallback collector.
* Shared case modules keep the implementations in step: `tests/test_ps_redaction.py` holds the
  redaction cases that the sh tests import, and `tests/proxy_cases.py` the proxy-detection cases.
* Pass multi-line test input through files, not command-line arguments: MSYS and cmd.exe
  mangle line breaks in arguments.
* Every report is validated against the schema; secret canaries must never appear in output.

Test-only hooks are environment variables and are recorded in the report (except the two below):
`ENVSCAN_ROOT` (sh: prefix for /etc, /proc, /sys reads -> `run.test_root`), and
`ENVSCAN_TEST_POLICY` (cmd: forces an execution-policy decision, one of `allowed`,
`restricted`, `allsigned-gpo`, `blocked`; printed in the fallback output), `ENVSCAN_TEST_WSH`
(cmd: stands in for the Windows Script Host settings, one of `disabled`, `signed`, `rules`,
and for code integrity, `wdac` (an active App Control for Business policy) or `sac` (Smart App
Control on); another value is ignored with a note; printed in the fallback output),
`ENVSCAN_TEST_PLATFORM` and `ENVSCAN_TEST_SH` (ps1 Unix shim, see the registry section). These
two are announced on stderr, not recorded in the report, which is sh's. `ENVSCAN_TEST_STUBS=1`
(sh) also lets `ES_STUB_*` variables through the child allowlist, so the command stubs in
`tests/stubs` still get their settings; it changes nothing else and is not recorded. `tests/test_ps_unix_shim.py`
runs the shim under 5.1 and, when found, a portable PowerShell 7 (`ENVSCAN_PWSH` or `%LOCALAPPDATA%\envscan-dev\pwsh`).
