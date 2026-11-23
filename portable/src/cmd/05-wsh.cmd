rem ## envscan.cmd part 05-wsh: --wsh, envscan.js under Windows Script Host (cscript.exe) when
rem ## PowerShell or envscan.ps1 is missing or a local execution policy blocks the script; the
rem ## restore after a child returned; the wsh: header line and the --wsh guidance.

rem ---------------------------------------------------------------- restore after a child
:es_restore
rem After PowerShell or cscript.exe returned, outside the script's setlocal: the script's
rem variables again, and what was parsed, from __ES_SV_* (set by the launch line once the child
rem ended; the values hold no quote).
call :es_init
call :es_where
set "__ES_ERR=%__ES_SV_ERR%"
set "__ES_CAP=%__ES_SV_CAP%"
set "__ES_WAS_RELAUNCHED=%__ES_SV_REL%"
set "__ES_OPT_OUT=%__ES_SV_OUT%"
set "__ES_OPT_ONLY=%__ES_SV_ONLY%"
set "__ES_OPT_SKIP=%__ES_SV_SKIP%"
set "__ES_OPT_LIST=%__ES_SV_LIST%"
set "__ES_OPT_VERSION=%__ES_SV_VER%"
set "__ES_IGNORED=%__ES_SV_IGN%"
set "__ES_OPT_WSH=%__ES_SV_WSH%"
set "__ES_KIND=%__ES_SV_KIND%"
for %%V in (ERR CAP REL OUT ONLY SKIP LIST VER IGN WSH KIND) do set "__ES_SV_%%V="
if defined __ES_OPT_WSH call :es_wsh_args
exit /b 0

:es_wsh_args
rem __ES_JSFWD again, from the restored options: it holds quotes, so it cannot be carried in
rem __ES_SV_*. __ES_IGNORED holds only option names and checked numbers. The order of the
rem options may differ from the command line; their meaning does not.
set "__ES_RB_OPT="
for %%A in (%__ES_IGNORED%) do call :es_wsh_args_word %%A
if defined __ES_OPT_OUT call :es_fwd_add --out __ES_OPT_OUT
if defined __ES_OPT_ONLY call :es_fwd_add --only __ES_OPT_ONLY
if defined __ES_OPT_SKIP call :es_fwd_add --skip __ES_OPT_SKIP
if defined __ES_OPT_LIST call :es_fwd_add --list-probes
if defined __ES_OPT_VERSION call :es_fwd_add --version
exit /b 0
:es_wsh_args_word
if defined __ES_RB_OPT (set "__ES_RB_V=%~1" & call :es_fwd_add %__ES_RB_OPT% __ES_RB_V & set "__ES_RB_OPT=" & exit /b 0)
if "%~1"=="--timeout" (set "__ES_RB_OPT=--timeout" & exit /b 0)
if "%~1"=="--budget" (set "__ES_RB_OPT=--budget" & exit /b 0)
call :es_fwd_add %~1
exit /b 0

rem ---------------------------------------------------------------- Windows Script Host
:es_wsh_check_args
rem cscript.exe takes every argument that starts with // as one of its own options, wherever it
rem stands; --out is the only value that can (the patterns and numbers cannot, and an argument
rem that is not an option is refused). Every --out is forwarded, so :es_parse_value_out sets
rem __ES_OUT_SLASH for any of them, not only the last.
if not defined __ES_OUT_SLASH exit /b 0
if not defined __ES_BADARG set "__ES_BADARG=--out cannot start with // together with --wsh: cscript.exe would take it as one of its own options"
exit /b 0

:es_try_wsh
rem Every way to the fallback while PowerShell cannot run envscan.ps1 passes here. envscan.js
rem runs only with --wsh, when the reason allows it (:es_wsh_allowed) and Windows Script Host
rem may run it (:es_wsh_ready); else __ES_WSH_WHY says why not and the fallback runs.
if not defined __ES_OPT_WSH goto :es_fallback
call :es_wsh_allowed
if not defined __ES_WSH_WHY call :es_wsh_ready
if defined __ES_WSH_WHY goto :es_fallback
>&2 echo envscan: --wsh: PowerShell cannot run envscan.ps1 here; running envscan.js with Windows Script Host, cscript.exe.
if defined __ES_WSH_NOTE >&2 echo envscan: note: %__ES_WSH_NOTE%
goto :es_wsh_launch

:es_wsh_allowed
rem PowerShell or envscan.ps1 missing, or an execution policy that is a local setting or the
rem default. Never with Group Policy, a policy that could not be read, application control
rem (which may govern WSH too), or a PowerShell that started and failed otherwise.
set "__ES_WSH_WHY="
if "%__ES_KIND%"=="missing" exit /b 0
if "%__ES_KIND%"=="noscript" exit /b 0
if "%__ES_KIND%"=="policy" goto :es_wsh_allowed_policy
if "%__ES_KIND%"=="refused" goto :es_wsh_allowed_policy
if "%__ES_KIND%"=="blocked" (set "__ES_WSH_WHY=PowerShell may be blocked by application control, which may govern Windows Script Host too" & exit /b 0)
set "__ES_WSH_WHY=PowerShell started but did not finish; --wsh is used only when PowerShell or envscan.ps1 is missing or a local execution policy blocks the script"
exit /b 0
:es_wsh_allowed_policy
if defined __ES_POL_UNREAD (set "__ES_WSH_WHY=the execution policy could not be read, so Group Policy cannot be ruled out" & exit /b 0)
if defined __ES_POL_GPO set "__ES_WSH_WHY=Group Policy enforces the execution policy, scope %__ES_POL_SCOPE%"
exit /b 0

:es_wsh_ready
rem The private temporary files (cscript.exe's error output, the registry reads), cscript.exe in
rem System32 (64-bit after the relaunch), envscan.js next to this script, and the settings of
rem Windows Script Host (ENVSCAN_TEST_WSH, for tests only, stands in for them).
if not defined __ES_CAP (set "__ES_WSH_WHY=no temporary folder of yours is writable, which --wsh needs" & exit /b 0)
if not defined __ES_ERR (set "__ES_WSH_WHY=no temporary folder of yours is writable, which --wsh needs" & exit /b 0)
if not exist "%__ES_SYS%\cscript.exe" (set "__ES_WSH_WHY=cscript.exe was not found in %__ES_SYS%" & exit /b 0)
if not exist "%__ES_DIR%envscan.js" (set "__ES_WSH_WHY=envscan.js is not next to envscan.cmd" & exit /b 0)
call :es_wsh_hook_note
if /i "%__ES_X%"=="disabled" (set "__ES_WSH_WHY=Windows Script Host is disabled - simulated by ENVSCAN_TEST_WSH=disabled" & exit /b 0)
if /i "%__ES_X%"=="signed" (set "__ES_WSH_WHY=Windows Script Host runs only trusted signed scripts here - simulated by ENVSCAN_TEST_WSH=signed" & exit /b 0)
if /i "%__ES_X%"=="rules" (set "__ES_WSH_WHY=Software Restriction Policies or AppLocker script rules are configured - simulated by ENVSCAN_TEST_WSH=rules" & exit /b 0)
call :es_wsh_ci
if defined __ES_WSH_WHY exit /b 0
goto :es_wsh_settings

:es_wsh_hook_note
rem __ES_X: the value of ENVSCAN_TEST_WSH when it is a known one; else empty, and __ES_WSH_NOTE
rem says that it was ignored.
set "__ES_X="
if not defined ENVSCAN_TEST_WSH exit /b 0
call :es_env_word ENVSCAN_TEST_WSH __ES_X
for %%H in (disabled signed rules wdac sac) do if /i "%__ES_X%"=="%%H" exit /b 0
set "__ES_X="
set "__ES_WSH_NOTE=ENVSCAN_TEST_WSH is not one of disabled, signed, rules, wdac, sac and was ignored"
exit /b 0

:es_wsh_ci
rem App Control for Business (WDAC) and Smart App Control may allow only signed or reputable
rem scripts, and they govern Windows Script Host. With the single-policy file SiPolicy.p7b (only
rem "if exist", nothing is opened, no child runs; Sysnative is the 64-bit System32 of a 32-bit
rem cmd.exe), or with Smart App Control on (1) or in evaluation (2), the script is not tried.
rem CiPolicies\Active is not used: Windows 11 keeps its inbox policies there (Smart App Control,
rem driver block list) even when nothing is enforced. __ES_X: the test hook (wdac, sac).
if /i "%__ES_X%"=="wdac" (set "__ES_WSH_WHY=App Control for Business (WDAC) policies are active - simulated by ENVSCAN_TEST_WSH=wdac" & exit /b 0)
if /i "%__ES_X%"=="sac" (set "__ES_WSH_WHY=Smart App Control is on or in evaluation - simulated by ENVSCAN_TEST_WSH=sac" & exit /b 0)
for %%G in ("%__ES_SYS%" "%__ES_WIN%\Sysnative") do if exist "%%~G\CodeIntegrity\SiPolicy.p7b" set "__ES_WSH_WHY=App Control for Business (WDAC) policies are active, %%~G\CodeIntegrity\SiPolicy.p7b, which may block envscan.js"
if defined __ES_WSH_WHY exit /b 0
call :es_reg_check
if defined __ES_REG_DEAD (set "__ES_WSH_WHY=reg.exe could not read the registry, so Smart App Control and the Windows Script Host settings are unknown" & exit /b 0)
call :es_reg_get "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" VerifiedAndReputablePolicyState __ES_T1
call :es_wsh_num __ES_T1 0
if not "%__ES_N%"=="0" set "__ES_WSH_WHY=Smart App Control is on or in evaluation, VerifiedAndReputablePolicyState is %__ES_N%, which may block envscan.js"
exit /b 0

:es_wsh_settings
rem Software\Microsoft\Windows Script Host\Settings of HKLM, then HKCU unless HKLM sets
rem IgnoreUserSettings. Unreadable settings count as forbidding the script.
call :es_reg_check
if defined __ES_REG_DEAD (set "__ES_WSH_WHY=reg.exe could not read the registry, so the Windows Script Host settings are unknown" & exit /b 0)
set "__ES_WSH_IGN="
call :es_wsh_scope HKLM
if defined __ES_WSH_WHY exit /b 0
if not "%__ES_WSH_IGN%"=="1" call :es_wsh_scope HKCU
if defined __ES_WSH_WHY exit /b 0
call :es_wsh_rules HKLM
if not defined __ES_WSH_WHY call :es_wsh_rules HKCU
if defined __ES_WSH_WHY exit /b 0
rem AppLocker script rules cover .js files: with any, the script is not tried.
"%__ES_SYS%\reg.exe" query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" <nul >"%__ES_CAP%" 2>nul && set "__ES_WSH_WHY=AppLocker script rules are configured, which may block envscan.js"
exit /b 0

:es_wsh_scope
rem Enabled 0 turns Windows Script Host off; a TrustPolicy other than 0 makes it ask before (1)
rem or refuse (2) a script that is not signed by a trusted publisher. __ES_WSH_IGN: HKLM's
rem IgnoreUserSettings.
call :es_reg_load "%~1\Software\Microsoft\Windows Script Host\Settings" "Enabled IgnoreUserSettings TrustPolicy"
call :es_wsh_num __ES_RV_Enabled 1
if "%__ES_N%"=="0" (set "__ES_WSH_WHY=Windows Script Host is disabled, Enabled is 0 in %~1" & exit /b 0)
call :es_wsh_num __ES_RV_TrustPolicy 0
if not "%__ES_N%"=="0" (set "__ES_WSH_WHY=Windows Script Host runs only trusted signed scripts here, TrustPolicy is %__ES_N% in %~1" & exit /b 0)
if /i not "%~1"=="HKLM" exit /b 0
call :es_wsh_num __ES_RV_IgnoreUserSettings 0
set "__ES_WSH_IGN=%__ES_N%"
exit /b 0

:es_wsh_num
rem __ES_N: the number held by the variable named by the first argument (set /a reads it by name,
rem so its text is never expanded), or the second argument when that variable is not set.
set "__ES_N=%~2"
if not defined %~1 exit /b 0
set /a "__ES_N=-1"
set /a "__ES_N=%~1" >nul 2>nul
exit /b 0

:es_wsh_rules
rem Software Restriction Policies, which Windows Script Host follows when UseWINSAFER is 1 (the
rem default of Windows): configured when CodeIdentifiers holds DefaultLevel or a rule level
rem subkey. Windows itself may create the key with authenticodeenabled only, which sets no rule.
type nul >"%__ES_CAP%"
"%__ES_SYS%\reg.exe" query "%~1\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" <nul >"%__ES_CAP%" 2>nul
"%__ES_SYS%\findstr.exe" /i /r /c:"CodeIdentifiers\\." /c:"^ *DefaultLevel " "%__ES_CAP%" >nul 2>nul || exit /b 0
set "__ES_WSH_WHY=Software Restriction Policies are configured in %~1, which Windows Script Host follows"
exit /b 0

:es_wsh_launch
rem As the PowerShell launch (see :es_main_run): endlocal first, so envscan.js sees the caller's
rem environment without this script's variables, with empty input, the short TMP and the checked
rem SystemRoot and SystemDrive (endlocal restores the caller's). Only this
rem child gets __ES_EXIT_BASE=100: envscan.js then exits 100 + its result, which cscript.exe
rem never returns on its own (0 after a runtime error or a timeout, 1 after a syntax error or
rem when WSH is disabled). Never //B, which hides the error text, and never wscript.exe.
endlocal & set "__ES_CAP=%__ES_CAP%" & call :es_clear_inherited all & (if not "%__ES_TMPFIX%"=="" set "TMP=%__ES_TMPFIX%") & set "SystemRoot=%__ES_WIN%" & set "SystemDrive=%__ES_SYSDRIVE%" & set "__ES_EXIT_BASE=100" & "%__ES_SYS%\cscript.exe" //nologo //E:jscript "%__ES_DIR%envscan.js"%__ES_JSFWD% <nul 2>"%__ES_ERR%" & call set "__ES_JS_RC=%%errorlevel%%" & set "__ES_EXIT_BASE=" & set "__ES_SV_ERR=%__ES_ERR%" & set "__ES_SV_CAP=%__ES_CAP%" & set "__ES_SV_REL=%__ES_WAS_RELAUNCHED%" & set "__ES_SV_OUT=%__ES_OPT_OUT%" & set "__ES_SV_ONLY=%__ES_OPT_ONLY%" & set "__ES_SV_SKIP=%__ES_OPT_SKIP%" & set "__ES_SV_LIST=%__ES_OPT_LIST%" & set "__ES_SV_VER=%__ES_OPT_VERSION%" & set "__ES_SV_IGN=%__ES_IGNORED%" & set "__ES_SV_WSH=%__ES_OPT_WSH%" & set "__ES_SV_KIND=%__ES_KIND%" & call :es_after_wsh
exit /b %errorlevel%

:es_after_wsh
rem Runs after cscript.exe returned, outside the script's setlocal: __ES_JS_RC is its exit code.
rem 100, 101 and 102 are envscan.js's results 0, 1 and 2; anything else means that WSH failed,
rem and the fallback runs with the reason PowerShell could not run and a wsh: line.
setlocal
call :es_restore
set /a "__ES_JS_RC=__ES_JS_RC" >nul 2>nul
set "__ES_PS_RC="
if "%__ES_JS_RC%"=="100" set "__ES_PS_RC=0"
if "%__ES_JS_RC%"=="101" set "__ES_PS_RC=1"
if "%__ES_JS_RC%"=="102" set "__ES_PS_RC=2"
if "%__ES_JS_RC%"=="-1073741510" set "__ES_PS_RC=-1073741510"
if defined __ES_PS_RC goto :es_ps_finish
set "__ES_WSH_RC=%__ES_JS_RC%"
call :es_wsh_hook_note
call :es_find_powershell
if "%__ES_KIND%"=="policy" call :es_predict_policy
if "%__ES_KIND%"=="refused" call :es_predict_policy
goto :es_fallback

rem ---------------------------------------------------------------- report and guidance
:es_wsh_header
rem The wsh: line of the fallback report (only with --wsh).
setlocal EnableDelayedExpansion
if defined __ES_WSH_RC (echo wsh: envscan.js ran with cscript.exe and ended with exit code !__ES_WSH_RC!, so the scan did not finish) else if defined __ES_WSH_WHY (echo wsh: not used: !__ES_WSH_WHY!) else if "!__ES_KIND!"=="forced" echo wsh: not used: --fallback was given
if defined __ES_WSH_NOTE echo note: !__ES_WSH_NOTE!
exit /b 0

:es_guidance_wsh
rem Console only, inside the delayed expansion of :es_guidance (only with --wsh).
if defined __ES_WSH_RC (echo envscan: --wsh: envscan.js did not finish the scan with Windows Script Host, cscript.exe exit code !__ES_WSH_RC!; its error output is in envscan-fallback.txt.& goto :es_guidance_wsh_note)
if defined __ES_WSH_WHY (echo envscan: --wsh was not used: !__ES_WSH_WHY!.& goto :es_guidance_wsh_note)
if "!__ES_KIND!"=="forced" echo envscan: --wsh was not used: --fallback was given.
:es_guidance_wsh_note
if defined __ES_WSH_NOTE echo envscan: note: !__ES_WSH_NOTE!
exit /b 0

:es_guidance_wsh_hint
rem Offered only where --wsh may run envscan.js: PowerShell or envscan.ps1 missing, or a local
rem execution policy (the callers in :es_guidance), with envscan.js and a private temporary folder,
rem and without App Control for Business or Smart App Control. Inside :es_guidance's setlocal, so
rem __ES_WSH_WHY set here does not reach the report.
if defined __ES_OPT_WSH exit /b 0
if not defined __ES_CAP exit /b 0
if not exist "!__ES_DIR!envscan.js" exit /b 0
rem Not where App Control for Business or Smart App Control would refuse it (:es_wsh_ci).
call :es_wsh_hook_note
set "__ES_WSH_WHY="
call :es_wsh_ci
if defined __ES_WSH_WHY exit /b 0
echo envscan: or run the full scan with Windows Script Host instead, which needs no PowerShell:
echo envscan:   envscan.cmd --wsh [options]
exit /b 0
