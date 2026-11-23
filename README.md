# EnvScan

Zero-install, cross-platform environment scanner. It tells a deployment team or a coding agent what a
locked-down or air-gapped host allows: OS and hardware, the running user's rights, runtimes and build
tools, package sources and offline caches, proxies and certificates, writable and executable paths, and
resource limits. No installation, no admin rights, and no network traffic by default.

- **Five implementations of one 53-probe spec:** PowerShell 2.0–7 (incl. Constrained Language mode),
  cmd.exe fallback, Windows Script Host, POSIX `sh` (Linux, macOS, BSD, AIX, Solaris), and static Go
  binaries for linux amd64, arm64, ppc64le and s390x.
- Built-in secret redaction, a JSON Schema for the report, and SHA-256-verified releases.
- 1,100+ tests.

## Layout

| Path | Contents |
|---|---|
| `portable/src/` | Sources for each implementation (`cmd`, `go`, PowerShell, shell, JScript) |
| `portable/spec/` | The probe, policy and redaction specs (TOML) |
| `portable/schema/` | JSON Schema for the report |
| `portable/docs/` | User guide (`README.dist.md`), probe catalog, acceptance criteria, developer notes |
| `portable/tests/` | Test suite |
| `scanner.py`, `scanner_gui.py` | The original Python prototype and its GUI |

See [`portable/docs/README.dist.md`](portable/docs/README.dist.md) for how to transfer, verify and run it.
