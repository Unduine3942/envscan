rem ## envscan.cmd part 30-probes: the fallback probes (labels :es_probe_<id with _>, one per entry
rem ## of spec/footprint/cmd.toml) and their helpers.

rem ---------------------------------------------------------------- probes
rem Programs write to the capture file __ES_CAP, which FOR /F then reads (see the top of the file);
rem the fallback always has one, in the temporary folder or in the output folder.
:es_probe_os_identity
set "__ES_HIT=1"
ver >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do echo ver: %%L
call :es_reg_values "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "" "ProductName DisplayVersion ReleaseId EditionID InstallationType CurrentBuild CurrentBuildNumber UBR CurrentMajorVersionNumber CurrentMinorVersionNumber BuildLabEx"
if not defined __ES_RV_CurrentBuild (set "__ES_ST=partial" & echo note: the build number could not be read from the registry)
set /a "__ES_X=0"
if defined __ES_RV_CurrentBuild set /a "__ES_X=__ES_RV_CurrentBuild" >nul 2>nul
if %__ES_X% GEQ 22000 echo note: build 22000 or later is Windows 11, even where ProductName says Windows 10
for %%V in (PROCESSOR_ARCHITECTURE PROCESSOR_ARCHITEW6432 OS) do call :es_show_env %%V
if defined __ES_WAS_RELAUNCHED (echo launcher: started by 32-bit cmd.exe, re-run in 64-bit cmd.exe) else (echo launcher: native cmd.exe)
exit /b 0

:es_probe_os_time_locale
set "__ES_HIT=1"
set "__ES_PFX=local_time: "
setlocal EnableDelayedExpansion
set "__ES_V=!date! !time!"
call :es_emit_value
endlocal
if defined __ES_STAMP_UTC echo utc_time: %__ES_STAMP_UTC%
call :es_reg_values "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" "" "TimeZoneKeyName ActiveTimeBias Bias DynamicDaylightTimeDisabled"
"%__ES_SYS%\tzutil.exe" /g <nul >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do echo tzutil: %%L
call :es_reg_values "HKCU\Control Panel\International" "" "LocaleName sShortDate sTimeFormat sDecimal sThousand sList iDate"
call :es_reg_values "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" "" "ACP OEMCP MACCP"
call :es_var_is __ES_RV_ACP 65001 && echo note: ACP 65001 means the system-wide UTF-8 option is on
call :es_codepage
if defined __ES_CP (echo console_code_page: %__ES_CP%) else (echo console_code_page: unknown)
exit /b 0

:es_probe_hw_cpu
set "__ES_HIT=1"
call :es_reg_values "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" "" "ProcessorNameString VendorIdentifier Identifier ~MHz"
for %%V in (NUMBER_OF_PROCESSORS PROCESSOR_IDENTIFIER PROCESSOR_LEVEL PROCESSOR_REVISION) do call :es_show_env %%V
set /a "__ES_N=0"
"%__ES_SYS%\reg.exe" query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1 delims=_" %%L in ("%__ES_CAP%") do if "%%L"=="HKEY" set /a "__ES_N+=1"
echo logical_processors_in_registry: %__ES_N%
exit /b 0

:es_probe_user_identity
set "__ES_HIT=1"
for %%V in (USERNAME USERDOMAIN USERDNSDOMAIN USERPROFILE HOMEDRIVE HOMEPATH HOMESHARE LOGONSERVER) do call :es_show_env %%V
set "__ES_T1="
"%__ES_SYS%\whoami.exe" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do set "__ES_T1=%%L"
if defined __ES_T1 (call :es_print_kv whoami __ES_T1) else (set "__ES_ST=partial" & echo whoami: not available)
if defined __ES_REG_DEAD (set "__ES_ST=partial" & echo elevated: unknown, reg.exe could not read the registry& exit /b 0)
"%__ES_SYS%\reg.exe" query "HKU\S-1-5-19" >nul 2>nul && (echo elevated: yes, administrator token) || (echo elevated: no, standard user token)
exit /b 0

:es_probe_env_path
set "__ES_HIT=1"
call :es_reg_show "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" Path machine_path_registry
call :es_reg_show "HKCU\Environment" Path user_path_registry
if not defined PATH (echo PATH: not set& set "__ES_ST=partial" & exit /b 0)
call :es_strlen PATH __ES_X
echo process_path_length: %__ES_X% characters
if not defined __ES_LOCALDRV call :es_local_drives
echo local_drives: %__ES_LOCALDRV%
echo process_path_entries:
set /a "__ES_PN=0, __ES_PMISS=0, __ES_PDUP=0, __ES_PSKIP=0"
set "__ES_CB=es_path_entry"
call :es_path_split
if defined __ES_PCUT (set "__ES_ST=partial" & echo note: PATH is longer than 7000 characters; only the entries in the first 7000 were checked)
echo summary: %__ES_PN% entries, %__ES_PMISS% missing, %__ES_PDUP% duplicates, %__ES_PSKIP% not checked
exit /b 0
:es_path_entry
set /a "__ES_PN+=1"
set "__ES_TAG=ok"
set "__ES_NOTE="
call :es_path_kind
if defined __ES_KIND_SKIP (set "__ES_TAG=%__ES_KIND_SKIP%" & set /a "__ES_PSKIP+=1" & goto :es_path_entry_print)
if defined __ES_KIND_DUP (set "__ES_TAG=duplicate" & set /a "__ES_PDUP+=1" & goto :es_path_entry_print)
if not defined __ES_E (set "__ES_TAG=empty entry" & goto :es_path_entry_print)
if exist "%__ES_E2%\" (
    if /i "%__ES_E2:~-22%"=="\Microsoft\WindowsApps" set "__ES_NOTE=  - app execution aliases; python.exe here may only open the Microsoft Store"
    goto :es_path_entry_print
)
if exist "%__ES_E2%" (set "__ES_TAG=not a directory") else (set "__ES_TAG=missing" & set /a "__ES_PMISS+=1")
:es_path_entry_print
setlocal EnableDelayedExpansion
echo(  [!__ES_TAG!] !__ES_E!!__ES_NOTE!
exit /b 0

:es_path_split
rem Calls the label named in __ES_CB once per PATH entry, entry in __ES_E, delayed expansion
rem off. Quotes are removed (no entry can break out of the quoted FOR list); a PATH over 7000
rem characters is cut at the last full entry.
set "__ES_PCUT="
if not defined PATH exit /b 0
set "__ES_P=%PATH:"=%"
call :es_strlen __ES_P __ES_PLEN
if %__ES_PLEN% LEQ 7000 goto :es_path_split_run
set "__ES_PCUT=1"
setlocal EnableDelayedExpansion
set "__ES_P=!__ES_P:~0,7000!"
rem __ES_X: the cut-off last entry plus a # sentinel (stays defined when the cut ends at a ;).
set "__ES_X=!__ES_P!#"
for /l %%I in (1,1,2000) do (set "__ES_X2=!__ES_X:*;=!" & if not "!__ES_X2!"=="!__ES_X!" set "__ES_X=!__ES_X2!")
call :es_strlen __ES_X __ES_LX
set /a "__ES_LX=7000-__ES_LX"
if !__ES_LX! LSS 1 (endlocal & set "__ES_P=" & exit /b 0)
for %%a in (!__ES_LX!) do set "__ES_P=!__ES_P:~0,%%a!"
for /f "eol=| delims=" %%x in ("!__ES_P!") do endlocal & set "__ES_P=%%x"
:es_path_split_run
for %%E in ("%__ES_P:;=" "%") do (
    set "__ES_E=%%~E"
    call :%__ES_CB%
)
exit /b 0

:es_path_kind
rem Classifies __ES_E (delayed expansion off): __ES_E2 is the entry without a trailing
rem backslash; __ES_KIND_SKIP says why it must not be touched; __ES_KIND_DUP marks repeats.
set "__ES_KIND_SKIP="
set "__ES_KIND_DUP="
set "__ES_E2=%__ES_E%"
if not defined __ES_E2 exit /b 0
if "%__ES_E2:~-1%"=="\" set "__ES_E2=%__ES_E2:~0,-1%"
if not defined __ES_E2 (set "__ES_KIND_SKIP=relative, not checked" & exit /b 0)
for /f "eol=| delims=" %%K in ("__ES_SEEN_%__ES_CB%_%__ES_E2%") do if defined %%K (set "__ES_KIND_DUP=1" & exit /b 0) else (set "%%K=1")
for /f "eol=| delims=%%" %%a in ("%__ES_E2%") do if not "%%a"=="%__ES_E2%" (set "__ES_KIND_SKIP=unexpanded variable, not checked" & exit /b 0)
if "%__ES_E2:~0,2%"=="\\" (set "__ES_KIND_SKIP=network, not checked" & exit /b 0)
if not "%__ES_E2:~1,1%"==":" (set "__ES_KIND_SKIP=relative, not checked" & exit /b 0)
if not defined __ES_LOCALDRV call :es_local_drives
for %%d in (%__ES_LOCALDRV:;= %) do if /i "%%d"=="%__ES_E2:~0,1%" exit /b 0
set "__ES_KIND_SKIP=not on a local volume, not checked"
exit /b 0

:es_probe_shell_info
set "__ES_HIT=1"
for %%V in (COMSPEC PATHEXT __PSLockdownPolicy PSExecutionPolicyPreference) do call :es_show_env %%V
call :es_reg_show "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" PowerShellVersion windows_powershell_2_engine
call :es_reg_show "HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" PowerShellVersion windows_powershell_5_engine
"%__ES_SYS%\reg.exe" query "HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions" /s /v SemanticVersion <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1,2,*" %%A in ("%__ES_CAP%") do if /i "%%A"=="SemanticVersion" echo powershell_7: %%C
if not defined __ES_PS call :es_find_powershell
if defined __ES_PS (call :es_print_kv powershell_for_envscan __ES_PS) else (echo powershell_for_envscan: none found)
call :es_reg_values "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "policy_MachinePolicy_" "EnableScripts ExecutionPolicy"
call :es_reg_values "HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "policy_UserPolicy_" "EnableScripts ExecutionPolicy"
call :es_reg_values "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" "policy_CurrentUser_" "ExecutionPolicy"
call :es_reg_values "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" "policy_LocalMachine_" "ExecutionPolicy"
if not defined __ES_POL if not defined __ES_POL_WHY call :es_predict_policy
call :es_policy_report
call :es_reg_show "HKCU\Software\Policies\Microsoft\Windows\System" DisableCMD cmd_disabled_by_policy
call :es_reg_show "HKCU\Software\Microsoft\Command Processor" AutoRun cmd_autorun_user
call :es_reg_show "HKLM\Software\Microsoft\Command Processor" AutoRun cmd_autorun_machine
call :es_reg_show "HKCU\Software\Microsoft\Windows Script Host\Settings" Enabled wsh_enabled_user
call :es_reg_show "HKLM\Software\Microsoft\Windows Script Host\Settings" Enabled wsh_enabled_machine
exit /b 0
:es_policy_report
rem When reg.exe could not read the registry the policy is unknown (and the probe partial).
if defined __ES_POL_UNREAD set "__ES_ST=partial"
setlocal EnableDelayedExpansion
set "__ES_X=would run"
if defined __ES_POL_BLOCK set "__ES_X=would be refused"
if defined __ES_PS_BLOCKED set "__ES_X=PowerShell blocked"
set "__ES_Y=no"
if defined __ES_POL_GPO set "__ES_Y=yes"
if defined __ES_POL_UNREAD (
    set "__ES_POL=unknown"
    set "__ES_POL_SCOPE=unknown"
    set "__ES_Y=unknown"
    set "__ES_X=unknown"
)
echo predicted_policy: !__ES_POL!
echo predicted_scope: !__ES_POL_SCOPE!
echo predicted_by_group_policy: !__ES_Y!
if defined __ES_ZONE (echo envscan_ps1_zone: !__ES_ZONE!) else (echo envscan_ps1_zone: none)
if defined __ES_SIGNED (echo envscan_ps1_signed: yes) else (echo envscan_ps1_signed: no)
echo predicted_result: !__ES_X!
if defined __ES_POL_UNREAD echo note: the execution policy could not be read: reg.exe could not read the registry, so neither Group Policy nor the other scopes are known
if defined __ES_HOOK_NOTE echo note: !__ES_HOOK_NOTE!
exit /b 0

:es_probe_sec_app_control
set "__ES_HIT=1"
call :es_show_env __PSLockdownPolicy
set /a "__ES_N=0"
set "__ES_ALK="
"%__ES_SYS%\reg.exe" query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /s /v EnforcementMode <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1,2,*" %%A in ("%__ES_CAP%") do if /i "%%A"=="EnforcementMode" (set "__ES_X=%%C" & call :es_applocker_line) else (set "__ES_ALK=%%A")
if "%__ES_N%"=="0" echo applocker: no rule collection is configured
call :es_reg_values "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" "srp_machine_" "DefaultLevel TransparentEnabled PolicyScope"
call :es_reg_values "HKCU\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" "srp_user_" "DefaultLevel"
call :es_reg_show "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" VerifiedAndReputablePolicyState smart_app_control_state
call :es_reg_show "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" Enabled hvci_enabled
set /a "__ES_N=0"
for %%F in ("%__ES_WIN%\System32\CodeIntegrity\CiPolicies\Active\*.cip") do (set /a "__ES_N+=1" & echo wdac_active_policy_file: %%~nxF)
echo wdac_active_policy_files: %__ES_N%
exit /b 0
:es_applocker_line
rem set /a reads the variable as a number (its text could hold an expression with assignments).
set /a "__ES_N+=1"
set /a "__ES_X=__ES_X" 2>nul
set "__ES_Y=audit only"
if "%__ES_X%"=="1" set "__ES_Y=enforced"
setlocal EnableDelayedExpansion
for %%K in ("!__ES_ALK!") do echo(applocker_%%~nxK: !__ES_Y!, EnforcementMode !__ES_X!
exit /b 0

:es_probe_pkg_installed
set "__ES_HIT=1"
set /a "__ES_PKT=0"
call :es_pkg_root "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" machine_64bit
call :es_pkg_root "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" machine_32bit
call :es_pkg_root "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" user
echo total: %__ES_PKT%
echo note: Microsoft Store apps and optional OS features are not listed by the cmd.exe fallback
if defined __ES_REG_DEAD (set "__ES_ST=partial" & echo note: reg.exe could not read the registry, so no package could be listed)
exit /b 0
:es_pkg_root
echo %~2: %~1
set "__ES_PKN="
set "__ES_PKV="
set /a "__ES_PKC=0"
"%__ES_SYS%\reg.exe" query "%~1" /s <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1,2,*" %%A in ("%__ES_CAP%") do (
    if /i "%%A"=="DisplayName" (set "__ES_PKN=%%C") else if /i "%%A"=="DisplayVersion" (set "__ES_PKV=%%C") else for /f "tokens=1 delims=_" %%h in ("%%A") do if "%%h"=="HKEY" (
        if defined __ES_PKN (
            set /a "__ES_PKC+=1"
            setlocal EnableDelayedExpansion
            if defined __ES_PKV (echo(  !__ES_PKN!  [!__ES_PKV!]) else (echo(  !__ES_PKN!)
            endlocal
        )
        set "__ES_PKN="
        set "__ES_PKV="
    )
)
if defined __ES_PKN (
    set /a "__ES_PKC+=1"
    setlocal EnableDelayedExpansion
    if defined __ES_PKV (echo(  !__ES_PKN!  [!__ES_PKV!]) else (echo(  !__ES_PKN!)
    endlocal
)
echo   entries: %__ES_PKC%
set /a "__ES_PKT+=__ES_PKC"
exit /b 0

:es_probe_tools_inventory
rem Same search as cmd.exe itself: every local PATH directory in order, every PATHEXT extension.
rem Directory listings only; nothing is executed, so versions are not collected here.
set "__ES_HIT=1"
set /a "__ES_NT=0"
for %%T in (@@ES_TOOLS_QUOTED@@) do for /f "tokens=1,2 delims=:" %%a in ("%%~T") do (
    set /a "__ES_NT+=1"
    for %%e in (%%b) do (set "__ES_TID_%%e=%%a" & set "__ES_FEXE_%%e=")
)
set "__ES_EXTS=.COM .EXE .BAT .CMD"
call :es_pathext || echo note: PATHEXT holds characters other than letters, digits, . _ - and ;, so .COM .EXE .BAT .CMD were searched
echo found on PATH, first match first; nothing is executed and versions are not collected:
set "__ES_CB=es_tools_dir"
call :es_path_split
if defined __ES_PCUT (set "__ES_ST=partial" & echo note: PATH is longer than 7000 characters; only the directories in the first 7000 were searched)
setlocal EnableDelayedExpansion
set "__ES_X="
set /a "__ES_C=0, __ES_M=0"
for %%T in (@@ES_TOOLS_QUOTED@@) do for /f "tokens=1,2 delims=:" %%a in ("%%~T") do (
    set "__ES_Y="
    for %%e in (%%b) do if defined __ES_FEXE_%%e set "__ES_Y=1"
    if defined __ES_Y (set /a "__ES_C+=1") else (set /a "__ES_M+=1" & set "__ES_X=!__ES_X! %%a")
)
echo tools_found: !__ES_C! of !__ES_NT!
echo not_found:!__ES_X!
exit /b 0
:es_pathext
rem __ES_EXTS from PATHEXT when it holds only letters, digits, . _ - and ; (exit code 1 otherwise).
if not defined PATHEXT exit /b 0
setlocal EnableDelayedExpansion
for /f "eol=. delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-;" %%x in ("a!PATHEXT!") do exit /b 1
set "__ES_X=!PATHEXT:;= !"
endlocal & set "__ES_EXTS=%__ES_X%"
exit /b 0
:es_tools_dir
call :es_path_kind
if not defined __ES_E2 exit /b 0
if defined __ES_KIND_SKIP exit /b 0
if defined __ES_KIND_DUP exit /b 0
if not exist "%__ES_E2%\" exit /b 0
set "__ES_ALIAS="
if /i "%__ES_E2:~-22%"=="\Microsoft\WindowsApps" set "__ES_ALIAS=  - app execution alias in WindowsApps"
for %%X in (%__ES_EXTS%) do for %%F in ("%__ES_E2%\*%%X") do if /i "%%~xF"=="%%X" if defined __ES_TID_%%~nF (
    set "__ES_F=%%~fF"
    set "__ES_FEXE_%%~nF=1"
    setlocal EnableDelayedExpansion
    echo(  !__ES_TID_%%~nF!: !__ES_F!!__ES_ALIAS!
    endlocal
)
exit /b 0

:es_probe_runtime_dotnet
set "__ES_HIT=1"
call :es_reg_load "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release Version"
if defined __ES_RV_Release (call :es_dotnet_fw) else if defined __ES_REG_DEAD (set "__ES_ST=partial" & echo net_framework_4: not read) else (echo net_framework_4: not installed)
echo net_framework_keys:
"%__ES_SYS%\reg.exe" query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do for /f "tokens=1 delims=_" %%h in ("%%L") do if "%%h"=="HKEY" echo   %%~nxL
set /a "__ES_N=0"
call :es_dotnet_env ProgramFiles dotnet
call :es_dotnet_env ProgramFiles(x86) dotnet
call :es_dotnet_env LOCALAPPDATA Microsoft\dotnet
call :es_dotnet_env USERPROFILE .dotnet
call :es_dotnet_env DOTNET_ROOT
if "%__ES_N%"=="0" echo dotnet: no .NET Core or .NET 5+ runtime in the standard locations
exit /b 0
:es_dotnet_fw
set /a "__ES_X=__ES_RV_Release" 2>nul
set "__ES_FW="
for %%M in (533320:4.8.1 528040:4.8 461808:4.7.2 461308:4.7.1 460798:4.7 394802:4.6.2 394254:4.6.1 393295:4.6 379893:4.5.2 378675:4.5.1 378389:4.5) do for /f "tokens=1,2 delims=:" %%a in ("%%M") do if not defined __ES_FW if %__ES_X% GEQ %%a set "__ES_FW=%%b"
if not defined __ES_FW set "__ES_FW=4.5 or earlier"
setlocal EnableDelayedExpansion
echo(net_framework_4: !__ES_FW!, Release !__ES_X!, Version !__ES_RV_Version!
exit /b 0
:es_dotnet_env
rem %1 variable, %2 subfolder. Network locations and folders on non-local drives are not read.
call :es_env_path %1 __ES_T || exit /b 0
if not "%~2"=="" set "__ES_T=%__ES_T%\%~2"
if "%__ES_T:~-1%"=="\" set "__ES_T=%__ES_T:~0,-1%"
call :es_seen_once __ES_T || exit /b 0
set "__ES_R="
if "%__ES_T:~0,2%"=="\\" (set "__ES_R=network location, not checked") else if not "%__ES_T:~1,2%"==":\" (set "__ES_R=not an absolute path, not checked")
if not defined __ES_R (
    if not defined __ES_LOCALDRV call :es_local_drives
    call :es_drive_is_local || set "__ES_R=not on a local volume, not checked"
)
if defined __ES_R (
    setlocal EnableDelayedExpansion
    echo(dotnet_root: !__ES_T! - !__ES_R!
    exit /b 0
)
if not exist "%__ES_T%\" exit /b 0
call :es_print_kv dotnet_root __ES_T
for /d %%F in ("%__ES_T%\shared\*") do for /d %%V in ("%%F\*") do (set /a "__ES_N+=1" & echo   runtime: %%~nxF %%~nxV)
for /d %%V in ("%__ES_T%\sdk\*") do echo   sdk: %%~nxV
exit /b 0

:es_probe_net_interfaces
set "__ES_HIT=1"
if not exist "%__ES_SYS%\ipconfig.exe" (echo ipconfig.exe not found& set "__ES_ST=error" & exit /b 0)
"%__ES_SYS%\ipconfig.exe" /all
exit /b 0

:es_probe_net_routes
set "__ES_HIT=1"
if not exist "%__ES_SYS%\route.exe" (echo route.exe not found& set "__ES_ST=error" & exit /b 0)
"%__ES_SYS%\route.exe" print
exit /b 0

:es_probe_net_proxy
set "__ES_HIT=1"
set /a "__ES_N=0"
for %%V in (@@ES_PROXY_ENV@@) do call :es_proxy_env %%~V
if "%__ES_N%"=="0" echo environment: no proxy variable is set
call :es_reg_values "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "wininet_user_" "ProxyEnable ProxyServer ProxyOverride AutoConfigURL AutoDetect"
call :es_reg_values "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" "wininet_policy_" "ProxySettingsPerUser"
call :es_var_is __ES_RV_ProxySettingsPerUser 0x0 && call :es_reg_values "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "wininet_machine_" "ProxyEnable ProxyServer ProxyOverride AutoConfigURL"
echo winhttp:
set "__ES_PFX=  "
"%__ES_SYS%\netsh.exe" winhttp show proxy <nul >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do (
    set "__ES_V=%%L"
    call :es_emit_value
)
exit /b 0
:es_proxy_env
if not defined %~1 exit /b 0
if defined __ES_PRX_%~1 exit /b 0
set "__ES_PRX_%~1=1"
set /a "__ES_N+=1"
call :es_show_env %~1
exit /b 0

:es_probe_fs_locations
rem A test file is written and deleted only in local folders outside Desktop, Documents and
rem OneDrive (a synced folder would upload it).
set "__ES_HIT=1"
if not defined __ES_LOCALDRV call :es_local_drives
call :es_fs_env TEMP TEMP
call :es_fs_env LOCALAPPDATA LOCALAPPDATA
call :es_fs_env LOCALAPPDATA LOCALAPPDATA\Programs Programs
call :es_fs_env APPDATA APPDATA
call :es_fs_env USERPROFILE USERPROFILE
call :es_fs_env ProgramData ProgramData
set "__ES_T=%__ES_CWD%"
call :es_fs_try current_directory
set "__ES_T=%__ES_DIR:~0,-1%"
call :es_fs_try script_directory
exit /b 0
:es_fs_env
rem %1 variable, %2 label, %3 optional subfolder.
set "__ES_T="
if not defined %~1 (echo %~2: not set& exit /b 0)
call :es_env_path %~1 __ES_T || (echo %~2: holds characters a path cannot contain, not tested& exit /b 0)
if not "%~3"=="" set "__ES_T=%__ES_T%\%~3"
:es_fs_try
set "__ES_R="
if not defined __ES_T (echo %~1: not set& exit /b 0)
call :es_fs_check
setlocal EnableDelayedExpansion
if "%~2"=="" (echo(%~1: !__ES_T! - !__ES_R!) else (echo(%~2: !__ES_T! - !__ES_R!)
exit /b 0
:es_fs_check
if "%__ES_T:~0,2%"=="\\" (set "__ES_R=network location, not tested" & exit /b 0)
if not "%__ES_T:~1,1%"==":" (set "__ES_R=not an absolute path, not tested" & exit /b 0)
call :es_drive_is_local || (set "__ES_R=not on a local volume, not tested" & exit /b 0)
call :es_personal_hit || goto :es_fs_check_write
set "__ES_R=inside %__ES_PFHIT%, which is never written to, not tested"
exit /b 0
:es_fs_check_write
if not exist "%__ES_T%\" (set "__ES_R=does not exist" & exit /b 0)
set "__ES_TF=%__ES_T%\envscan-probe-%RANDOM%%RANDOM%.tmp"
if exist "%__ES_TF%" (set "__ES_R=not tested, the test file name exists" & exit /b 0)
((echo envscan write test) >"%__ES_TF%") 2>nul || (set "__ES_R=not writable" & exit /b 0)
del /f /q "%__ES_TF%" >nul 2>nul
if exist "%__ES_TF%" (set "__ES_R=writable, but the test file could not be deleted" & set "__ES_ST=partial" & exit /b 0)
set "__ES_R=writable"
exit /b 0
:es_drive_is_local
setlocal EnableDelayedExpansion
set "__ES_DL=!__ES_T:~0,1!"
for %%d in ("!__ES_DL!") do if "!__ES_LOCALDRV:;%%~d;=!"=="!__ES_LOCALDRV!" exit /b 1
exit /b 0
:es_is_under
rem Exit code 0 when __ES_T is the folder named by the variable in the argument or inside it.
setlocal EnableDelayedExpansion
set "__ES_RT=!%~1!"
if not defined __ES_RT exit /b 1
call :es_strlen __ES_RT __ES_LR
for %%a in (!__ES_LR!) do (
    if /i not "!__ES_T:~0,%%a!"=="!__ES_RT!" exit /b 1
    if "!__ES_T:~%%a,1!"=="" exit /b 0
    if "!__ES_T:~%%a,1!"=="\" exit /b 0
)
exit /b 1

:es_probe_session_context
set "__ES_HIT=1"
for %%V in (SESSIONNAME CLIENTNAME WT_SESSION TERM_PROGRAM TERM ConEmuANSI) do call :es_show_env %%V
call :es_print_kv script __ES_SELF
call :es_print_kv started_in __ES_CWD
if defined __ES_CWD_NOTE call :es_print_kv started_in_note __ES_CWD_NOTE
call :es_codepage
if defined __ES_CP (echo console_code_page: %__ES_CP%) else (echo console_code_page: unknown)
exit /b 0
