<#
    envscan.ps1 - portable environment scanner for Windows.

    Describes everything on this machine that can affect an application: OS, hardware,
    limits, user and profile, environment, shells, application control, crypto and TLS
    trust, package sources and caches, installed runtimes and tools, network and proxy,
    file system behaviour, processes, services, virtualization and session.

    Runs on Windows PowerShell 2.0 through PowerShell 7, in FullLanguage and in
    ConstrainedLanguage mode, as a standard user. It only reads the system; the only
    writes are its output folder and self-deleting test files. The default tier sends
    no network traffic. Usually started by envscan.cmd.

    Usage: envscan.ps1 [--deep] [--net] [--out DIR] [--only IDS] [--skip IDS]
                       [--timeout SEC] [--budget SEC] [--no-redact]
                       [--list-probes] [--version] [--help]
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'
$script:ES_ARGS = @($args)
$script:ES_SCRIPT_PATH = $MyInvocation.MyCommand.Path
