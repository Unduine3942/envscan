rem ## envscan.cmd part 10-fallback-core: the reduced cmd.exe collector (reason and guidance, report
rem ## header, probe runner with --only/--skip and their pattern checks, summary), output folder,
rem ## personal and synced folders, UTC time stamp and the digit-run reader for localized text.

rem ---------------------------------------------------------------- fallback collector
:es_fallback
if defined __ES_OPT_VERSION (call :es_cleanup_temp & echo envscan %__ES_VERSION% ^(cmd^)& exit /b 0)
if defined __ES_OPT_LIST (call :es_cleanup_temp & call :es_list_probes & exit /b 0)
call :es_clear_inherited
call :es_reason
call :es_guidance 1>&2
if not defined __ES_PS if not "%__ES_KIND%"=="missing" call :es_find_powershell
call :es_output_folder
if not defined __ES_OUTDIR goto :es_fallback_nofolder
set "__ES_FILE=%__ES_OUTDIR%\envscan-fallback.txt"
if not defined __ES_CAP call :es_capture_in_output
if not defined __ES_CAP goto :es_fallback_nofolder
call :es_clear_inherited
call :es_reg_check
call :es_header >"%__ES_FILE%"
call :es_cleanup_err
pushd "%__ES_SYSDRIVE%\" >nul 2>nul
for %%P in (%__ES_PROBES%) do call :es_run_probe %%P
popd
call :es_summary >>"%__ES_FILE%"
call :es_cleanup_temp
>&2 echo envscan: reduced report written to envscan-fallback.txt in the folder printed below.
call :es_print_kv "" __ES_OUTDIR
exit /b %__ES_RC%
:es_fallback_badarg
call :es_cleanup_temp
rem The argument may be a secret (--password=x): it is echoed through the value rules.
set "__ES_PFX=envscan: "
setlocal EnableDelayedExpansion
set "__ES_V=!__ES_BADARG!"
>&2 call :es_emit_value
endlocal
>&2 call :es_usage
exit /b 2
:es_fallback_nofolder
call :es_cleanup_temp
>&2 echo envscan: cannot create an output folder; use --out DIR
exit /b 2

:es_capture_in_output
rem Without a private temporary folder the output of programs goes to a file in the output
rem folder, deleted at the end; env.vars then still lists the environment through a FOR /F
rem child, so the unredacted environment is never written there.
set "__ES_T=%__ES_OUTDIR%\envscan-capture.tmp"
(type nul >"%__ES_T%") 2>nul || exit /b 0
set "__ES_CAP=%__ES_T%"
set "__ES_CAP_OUT=1"
exit /b 0

:es_reason
set "__ES_REASON=PowerShell could not run envscan.ps1"
if "%__ES_KIND%"=="forced" set "__ES_REASON=--fallback was given"
if "%__ES_KIND%"=="missing" set "__ES_REASON=Windows PowerShell was not found and pwsh.exe is not on PATH"
if "%__ES_KIND%"=="noscript" set "__ES_REASON=envscan.ps1 is not next to envscan.cmd"
if "%__ES_KIND%"=="policy" set "__ES_REASON=%__ES_POL_WHY%"
if "%__ES_KIND%"=="blocked" set "__ES_REASON=%__ES_POL_WHY%"
if "%__ES_KIND%"=="refused" set "__ES_REASON=PowerShell refused to load envscan.ps1 - execution policy or signature check"
if "%__ES_KIND%"=="failed" set "__ES_REASON=PowerShell ended with exit code %__ES_PS_RC% before the scan could run"
exit /b 0

:es_guidance
rem Console only (stderr): the report file never holds the process-scoped command line, and it
rem is offered only when the policy was read and is not enforced by Group Policy.
setlocal EnableDelayedExpansion
echo envscan: running the reduced cmd.exe fallback collector: !__ES_REASON!.
if defined __ES_OPT_WSH call :es_guidance_wsh
if "!__ES_KIND!"=="policy" goto :es_guidance_policy
if "!__ES_KIND!"=="refused" goto :es_guidance_policy
if "!__ES_KIND!"=="failed" goto :es_guidance_control
if "!__ES_KIND!"=="blocked" goto :es_guidance_control
if "!__ES_KIND!"=="missing" echo envscan: Windows PowerShell ships with every supported Windows version; ask IT why it is missing here.
if "!__ES_KIND!"=="noscript" echo envscan: copy envscan.ps1 next to envscan.cmd to run the full scan.
for %%K in (missing noscript) do if "!__ES_KIND!"=="%%K" call :es_guidance_wsh_hint
goto :es_guidance_end
:es_guidance_policy
if defined __ES_POL_UNREAD goto :es_guidance_unread
if defined __ES_POL_GPO goto :es_guidance_gpo
echo envscan: for the full scan, if your organisation's rules allow it, run envscan.ps1 once with a
echo envscan: process-scoped execution policy. It changes no setting and affects only that one
echo envscan: PowerShell process:
echo envscan:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "!__ES_PS1!" [options]
if defined __ES_DOWNLOADED echo envscan: or remove the downloaded-file mark: right-click envscan.ps1, Properties, Unblock.
if "!__ES_DIR:~0,2!"=="\\" echo envscan: or copy the envscan folder to a local disk and run it from there.
call :es_guidance_wsh_hint
goto :es_guidance_end
:es_guidance_gpo
echo envscan: the execution policy is enforced by Group Policy, scope !__ES_POL_SCOPE!; do not try to
echo envscan: override it. For the full scan, ask IT or security to sign envscan.ps1 with a trusted
echo envscan: code-signing certificate or to allow it.
goto :es_guidance_end
:es_guidance_unread
echo envscan: the execution policy could not be read because reg.exe could not read the
echo envscan: registry, so whether Group Policy enforces it is unknown. Ask IT or security how
echo envscan: envscan.ps1 may run here; do not try to work around the policy.
goto :es_guidance_end
:es_guidance_control
echo envscan: application control such as AppLocker, WDAC or Software Restriction Policies may
echo envscan: block powershell.exe here. Ask IT or security; do not try to work around it.
:es_guidance_end
if defined __ES_HOOK_NOTE echo envscan: note: !__ES_HOOK_NOTE!
exit /b 0

:es_list_probes
@@ES_LIST_PROBES@@
exit /b 0

:es_header
setlocal EnableDelayedExpansion
echo envscan !__ES_VERSION! (cmd) - reduced fallback report
echo.
echo This is NOT the full envscan report. envscan.ps1 did not run, so cmd.exe collected only
echo what it can read on its own. Section names are the probe ids of the full scan.
echo.
echo reason: !__ES_REASON!
if not "!__ES_KIND!"=="forced" echo next_step: the full scan did not run; see the console output of envscan.cmd or the README section "When Windows blocks the script"
if defined __ES_HOOK_NOTE echo note: !__ES_HOOK_NOTE!
if defined __ES_OPT_WSH call :es_wsh_header
endlocal
call :es_ps_error_text
call :es_codepage
setlocal EnableDelayedExpansion
echo.
echo generated_local: !date! !time!
if defined __ES_STAMP_UTC (echo generated_utc: !__ES_STAMP_UTC!) else (echo generated_utc: unknown, the local date format could not be read)
echo computer: !COMPUTERNAME!
echo script: !__ES_SELF!
echo started_in: !__ES_CWD!
if defined __ES_CWD_NOTE echo started_in_note: !__ES_CWD_NOTE!
if defined __ES_OUT_SKIPPED echo output_skipped:!__ES_OUT_SKIPPED!
if defined __ES_PS (echo powershell: !__ES_PS!) else (echo powershell: not found)
if defined ENVSCAN_TEST_POLICY echo test_hook: ENVSCAN_TEST_POLICY=!ENVSCAN_TEST_POLICY!
if defined ENVSCAN_TEST_WSH echo test_hook: ENVSCAN_TEST_WSH=!ENVSCAN_TEST_WSH!
if defined __ES_OPT_ONLY echo only: !__ES_OPT_ONLY!
if defined __ES_OPT_SKIP echo skip: !__ES_OPT_SKIP!
if defined __ES_IGNORED echo ignored_options:!__ES_IGNORED! - only envscan.ps1 implements them
echo redaction: on - values of secret-looking names and passwords in URLs are replaced by !__ES_PH!
if defined __ES_REG_DEAD echo registry: reg.exe could not read the registry; values from it are reported as not read
if defined __ES_CP (echo encoding: console code page !__ES_CP!) else (echo encoding: console code page unknown)
echo format: each section starts with "=== probe: ID ===" and ends with "status: STATUS"
echo         ^(ok, partial, error or not_found^); a summary follows the last section.
exit /b 0

:es_ps_error_text
if not defined __ES_ERR exit /b 0
if not exist "%__ES_ERR%" exit /b 0
for %%F in ("%__ES_ERR%") do if %%~zF EQU 0 exit /b 0
echo.
if defined __ES_WSH_RC (echo error output of cscript.exe running envscan.js:) else echo PowerShell error output:
set "__ES_PFX=  "
for /f "usebackq delims=" %%L in ("%__ES_ERR%") do (
    set "__ES_V=%%L"
    call :es_emit_value
)
exit /b 0

:es_run_probe
set "__ES_PID=%~1"
set "__ES_LBL=es_probe_%__ES_PID:.=_%"
set "__ES_ST=ok"
set "__ES_HIT="
>>"%__ES_FILE%" echo.
>>"%__ES_FILE%" echo === probe: %__ES_PID% ===
call :es_selected "%__ES_PID%" || goto :es_run_probe_skip
>&2 echo envscan: %__ES_PID%
call :%__ES_LBL% >>"%__ES_FILE%" 2>&1
if not defined __ES_HIT (
    set "__ES_ST=error"
    >>"%__ES_FILE%" echo error: envscan.cmd has no implementation for this probe
)
>>"%__ES_FILE%" echo status: %__ES_ST%
set "__ES_SUMMARY=%__ES_SUMMARY% %__ES_PID%:%__ES_ST%"
if "%__ES_ST%"=="partial" set "__ES_RC=1"
if "%__ES_ST%"=="error" set "__ES_RC=1"
exit /b 0
:es_run_probe_skip
>>"%__ES_FILE%" echo note: not selected by --only or --skip
>>"%__ES_FILE%" echo status: skipped
set "__ES_SUMMARY=%__ES_SUMMARY% %__ES_PID%:skipped"
exit /b 0

:es_selected
rem Exit code 0 when the probe id in the first argument passes --only and --skip
rem (comma-separated patterns, checked by :es_check_patterns).
if not defined __ES_OPT_ONLY goto :es_selected_skip
set "__ES_REST=%__ES_OPT_ONLY%"
:es_selected_only
call :es_next_pattern || exit /b 1
call :es_match "%~1" || goto :es_selected_only
:es_selected_skip
if not defined __ES_OPT_SKIP exit /b 0
set "__ES_REST=%__ES_OPT_SKIP%"
:es_selected_skip_next
call :es_next_pattern || exit /b 0
call :es_match "%~1" && exit /b 1
goto :es_selected_skip_next
:es_next_pattern
rem The first pattern of __ES_REST in __ES_PAT, the others back in __ES_REST (the leading comma
rem keeps a line that starts with ; from being skipped as a comment by FOR /F).
set "__ES_X=%__ES_REST%"
set "__ES_REST="
set "__ES_PAT="
if not defined __ES_X exit /b 1
for /f "tokens=1* delims=, " %%a in (",%__ES_X%") do (set "__ES_PAT=%%a" & set "__ES_REST=%%b")
if not defined __ES_PAT exit /b 1
exit /b 0

:es_match
rem Exit code 0 when the probe id in the first argument matches the pattern __ES_PAT, where * is
rem any text (also none) and case is ignored, as PowerShell's -like: the id starts with the text
rem before the first *, holds the text between two * in order and ends with the text after the
rem last * (the # around both mark the start and the end).
setlocal EnableDelayedExpansion
set "__ES_MI=#%~1#"
set "__ES_MP=#!__ES_PAT!#"
if not "!__ES_MP!"=="!__ES_MP:**=!" goto :es_match_wild
if /i "!__ES_MI!"=="!__ES_MP!" exit /b 0
exit /b 1
:es_match_wild
set "__ES_MR=!__ES_MP:**=!"
call :es_strlen __ES_MP __ES_ML
call :es_strlen __ES_MR __ES_MRL
set /a "__ES_X=__ES_ML-__ES_MRL-1"
for %%n in (!__ES_X!) do (
    if /i not "!__ES_MI:~0,%%n!"=="!__ES_MP:~0,%%n!" exit /b 1
    set "__ES_MI=!__ES_MI:~%%n!"
)
set "__ES_MP=!__ES_MR!"
:es_match_part
if "!__ES_MP!"=="!__ES_MP:**=!" goto :es_match_end
set "__ES_MR=!__ES_MP:**=!"
call :es_strlen __ES_MP __ES_ML
call :es_strlen __ES_MR __ES_MRL
set /a "__ES_X=__ES_ML-__ES_MRL-1"
if !__ES_X! GTR 0 (
    for %%n in (!__ES_X!) do set "__ES_S=!__ES_MP:~0,%%n!"
    for /f "delims=" %%s in ("!__ES_S!") do set "__ES_Y=!__ES_MI:*%%s=!"
    if "!__ES_Y!"=="!__ES_MI!" exit /b 1
    set "__ES_MI=!__ES_Y!"
)
set "__ES_MP=!__ES_MR!"
goto :es_match_part
:es_match_end
call :es_strlen __ES_MP __ES_ML
call :es_strlen __ES_MI __ES_MIL
if !__ES_MIL! LSS !__ES_ML! exit /b 1
for %%n in (!__ES_ML!) do if /i "!__ES_MI:~-%%n!"=="!__ES_MP!" exit /b 0
exit /b 1

:es_check_patterns
rem The patterns of __ES_REST, given to the option in the first argument (--only or --skip): each
rem holds letters, digits, . _ - * only and matches at least one probe of the full scan, as
rem envscan.ps1 checks them; else __ES_BADARG names the first that does not.
:es_check_patterns_next
call :es_next_pattern || exit /b 0
call :es_pat_ok || goto :es_check_patterns_bad
call :es_known_pattern && goto :es_check_patterns_next
if not defined __ES_BADARG set "__ES_BADARG=%~1: pattern '%__ES_PAT%' matches no probe"
exit /b 0
:es_check_patterns_bad
if not defined __ES_BADARG set "__ES_BADARG=%~1: invalid pattern '%__ES_PAT%' (allowed: letters, digits, . _ - *)"
exit /b 0
:es_pat_ok
setlocal EnableDelayedExpansion
for /f "eol=. delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._*-" %%x in ("a!__ES_PAT!") do exit /b 1
exit /b 0
:es_known_pattern
for %%I in (%__ES_ALLIDS%) do if /i "%%I"=="%__ES_PAT%" exit /b 0
if "%__ES_PAT%"=="%__ES_PAT:**=%" exit /b 1
for %%I in (%__ES_ALLIDS%) do call :es_match "%%I" && exit /b 0
exit /b 1

:es_summary
echo.
echo === summary ===
for %%S in (%__ES_SUMMARY%) do for /f "tokens=1,2 delims=:" %%a in ("%%S") do echo %%a: %%b
if "%__ES_RC%"=="0" (echo result: complete) else (echo result: incomplete, see the sections whose status is not ok)
exit /b 0

rem ---------------------------------------------------------------- output folder
:es_output_folder
rem envscan-HOST-STAMP under --out as given; else under the first of the current directory, the
rem profile and TEMP that :es_output_safe accepts and where the folder can be created.
set "__ES_OUTDIR="
set "__ES_OUT_SKIPPED="
call :es_env_word COMPUTERNAME __ES_HOST || set "__ES_HOST=host"
call :es_utc_stamp || set "__ES_STAMP="
if defined __ES_STAMP (set "__ES_STAMP_UTC=%__ES_STAMP%") else (set "__ES_STAMP_UTC=" & set "__ES_STAMP=R%RANDOM%%RANDOM%")
set "__ES_NAME=envscan-%__ES_HOST%-%__ES_STAMP%"
if defined __ES_OPT_OUT goto :es_output_opt
set "__ES_T=%__ES_CWD%"
call :es_output_default current_directory && exit /b 0
call :es_env_path USERPROFILE __ES_T
call :es_output_default USERPROFILE && exit /b 0
call :es_env_path TEMP __ES_T
call :es_output_default TEMP
exit /b 0
:es_output_default
if not defined __ES_T exit /b 1
call :es_output_safe || goto :es_output_skip
call :es_output_try && exit /b 0
set "__ES_WHY=cannot be written to"
:es_output_skip
set "__ES_OUT_SKIPPED=%__ES_OUT_SKIPPED% %~1 (%__ES_WHY%)"
exit /b 1
:es_output_opt
for %%A in ("%__ES_OPT_OUT%") do set "__ES_T=%%~fA"
if not exist "%__ES_T%\" mkdir "%__ES_T%" >nul 2>nul
call :es_output_try
exit /b 0
:es_output_try
if not defined __ES_T exit /b 1
if not exist "%__ES_T%\" exit /b 1
if "%__ES_T:~-1%"=="\" set "__ES_T=%__ES_T:~0,-1%"
if exist "%__ES_T%\%__ES_NAME%" set "__ES_NAME=%__ES_NAME%-%RANDOM%"
mkdir "%__ES_T%\%__ES_NAME%" >nul 2>nul || exit /b 1
((echo envscan) >"%__ES_T%\%__ES_NAME%\envscan-fallback.txt") 2>nul || (rmdir "%__ES_T%\%__ES_NAME%" >nul 2>nul & exit /b 1)
set "__ES_OUTDIR=%__ES_T%\%__ES_NAME%"
exit /b 0

:es_output_safe
rem Exit code 0 when a default output folder may go under __ES_T: on a local drive, outside the
rem Windows directory, Desktop, Documents and OneDrive (the report could leave the machine from
rem a synced or network folder). Else __ES_WHY says why not.
set "__ES_WHY=network location"
if "%__ES_T:~0,2%"=="\\" exit /b 1
set "__ES_WHY=not an absolute path"
if not "%__ES_T:~1,2%"==":\" exit /b 1
set "__ES_WHY=not on a local volume"
if not defined __ES_LOCALDRV call :es_local_drives
call :es_drive_is_local || exit /b 1
set "__ES_WHY=Windows directory"
call :es_is_under __ES_WIN && exit /b 1
call :es_personal_hit || exit /b 0
set "__ES_WHY=%__ES_PFHIT%"
exit /b 1

rem ---------------------------------------------------------------- personal and synced folders
:es_personal_load
rem __ES_PF_1 to __ES_PF_<__ES_PFN>, labels in __ES_PFL_n: Desktop and Documents of the profile,
rem their paths in User Shell Folders and Shell Folders (redirected, OneDrive), and the OneDrive
rem roots. Nothing is written there: they belong to the user, and synced folders upload files.
if defined __ES_PFN exit /b 0
set /a "__ES_PFN=0"
call :es_env_path USERPROFILE __ES_UP
set "__ES_PFT="
if defined __ES_UP set "__ES_PFT=%__ES_UP%\Desktop"
call :es_pf_add Desktop
if defined __ES_UP set "__ES_PFT=%__ES_UP%\Documents"
call :es_pf_add Documents
call :es_reg_load "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" "Desktop Personal {F42EE2D3-909F-4907-8871-4C22FC0BF756}"
call :es_pf_reg __ES_RV_Desktop Desktop
call :es_pf_reg __ES_RV_Personal Documents
call :es_pf_reg __ES_RV_{F42EE2D3-909F-4907-8871-4C22FC0BF756} Documents
call :es_reg_load "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "Desktop Personal"
call :es_pf_reg __ES_RV_Desktop Desktop
call :es_pf_reg __ES_RV_Personal Documents
for %%V in (OneDrive OneDriveCommercial OneDriveConsumer) do (
    call :es_env_path %%V __ES_PFT
    call :es_pf_add OneDrive
)
exit /b 0
:es_pf_reg
rem A folder from the registry: a leading %USERPROFILE% becomes the checked profile path; a path
rem with any other % is left out (cmd.exe cannot expand it safely).
call :es_env_path %1 __ES_PFT || exit /b 0
setlocal EnableDelayedExpansion
if /i "!__ES_PFT:~0,13!"=="%%USERPROFILE%%" (
    if not defined __ES_UP exit /b 0
    set "__ES_PFT=!__ES_UP!!__ES_PFT:~13!"
)
if not "!__ES_PFT:%%=!"=="!__ES_PFT!" exit /b 0
for /f "eol=| delims=" %%v in ("!__ES_PFT!") do endlocal & set "__ES_PFT=%%v"
call :es_pf_add %2
exit /b 0
:es_pf_add
if not defined __ES_PFT exit /b 0
if "%__ES_PFT:~-1%"=="\" set "__ES_PFT=%__ES_PFT:~0,-1%"
if not defined __ES_PFT exit /b 0
set /a "__ES_PFN+=1"
set "__ES_PF_%__ES_PFN%=%__ES_PFT%"
set "__ES_PFL_%__ES_PFN%=%~1"
exit /b 0

:es_personal_hit
rem Exit code 0 when __ES_T is a folder of :es_personal_load or inside one; its label is left in
rem __ES_PFHIT.
call :es_personal_load
set "__ES_PFHIT="
for /l %%n in (1,1,%__ES_PFN%) do if not defined __ES_PFHIT call :es_is_under __ES_PF_%%n && set "__ES_PFHIT=%%n"
if not defined __ES_PFHIT exit /b 1
call set "__ES_PFHIT=%%__ES_PFL_%__ES_PFHIT%%%"
exit /b 0

rem ---------------------------------------------------------------- time and localized text
:es_utc_stamp
rem UTC = local time + ActiveTimeBias minutes. Date and time are read as runs of digits (formats
rem such as 2026/11/11(Wed) or Mi 11.11.2026); the order of day, month and year comes from the
rem user's locale.
set "__ES_STAMP="
call :es_reg_get "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" ActiveTimeBias __ES_TB
call :es_env_word __ES_TB __ES_TB || exit /b 1
call :es_reg_get "HKCU\Control Panel\International" iDate __ES_TI
call :es_env_word __ES_TI __ES_TI
call :es_digit_groups date
if not defined __ES_G3 exit /b 1
set "__ES_P1=%__ES_G1%" & set "__ES_P2=%__ES_G2%" & set "__ES_P3=%__ES_G3%"
if not "%__ES_P1:~3,1%"=="" (set "__ES_Y=%__ES_P1%" & set "__ES_M=%__ES_P2%" & set "__ES_D=%__ES_P3%" & goto :es_utc_time)
if "%__ES_TI%"=="1" (set "__ES_Y=%__ES_P3%" & set "__ES_M=%__ES_P2%" & set "__ES_D=%__ES_P1%" & goto :es_utc_time)
if "%__ES_TI%"=="2" (set "__ES_Y=%__ES_P1%" & set "__ES_M=%__ES_P2%" & set "__ES_D=%__ES_P3%" & goto :es_utc_time)
set "__ES_Y=%__ES_P3%" & set "__ES_M=%__ES_P1%" & set "__ES_D=%__ES_P2%"
:es_utc_time
call :es_digit_groups time
if not defined __ES_G3 exit /b 1
set "__ES_H=%__ES_G1%" & set "__ES_MI=%__ES_G2%" & set "__ES_S=%__ES_G3%"
set "__ES_Y=0000%__ES_Y%" & set "__ES_M=00%__ES_M%" & set "__ES_D=00%__ES_D%"
set "__ES_H=00%__ES_H%" & set "__ES_MI=00%__ES_MI%" & set "__ES_S=00%__ES_S%"
set /a "__ES_Y=1%__ES_Y:~-4% %% 10000, __ES_M=1%__ES_M:~-2% %% 100, __ES_D=1%__ES_D:~-2% %% 100"
set /a "__ES_H=1%__ES_H:~-2% %% 100, __ES_MI=1%__ES_MI:~-2% %% 100, __ES_S=1%__ES_S:~-2% %% 100"
if %__ES_Y% LSS 100 set /a "__ES_Y+=2000"
if %__ES_M% LSS 1 exit /b 1
if %__ES_M% GTR 12 exit /b 1
if %__ES_D% LSS 1 exit /b 1
if %__ES_D% GTR 31 exit /b 1
if %__ES_H% GTR 23 exit /b 1
if %__ES_MI% GTR 59 exit /b 1
if %__ES_S% GTR 60 exit /b 1
set /a "__ES_T=__ES_H*60+__ES_MI+(%__ES_TB%), __ES_SH=0"
if %__ES_T% LSS 0 set /a "__ES_T+=1440, __ES_SH=-1"
if %__ES_T% GEQ 1440 set /a "__ES_T-=1440, __ES_SH=1"
set /a "__ES_H=__ES_T/60, __ES_MI=__ES_T%%60"
if "%__ES_SH%"=="1" call :es_day_next
if "%__ES_SH%"=="-1" call :es_day_prev
set /a "__ES_M=100+__ES_M, __ES_D=100+__ES_D, __ES_H=100+__ES_H, __ES_MI=100+__ES_MI, __ES_S=100+__ES_S"
set "__ES_STAMP=%__ES_Y%%__ES_M:~1%%__ES_D:~1%T%__ES_H:~1%%__ES_MI:~1%%__ES_S:~1%Z"
exit /b 0
:es_day_next
call :es_dim
set /a "__ES_D+=1"
if %__ES_D% LEQ %__ES_DIM% exit /b 0
set /a "__ES_D=1, __ES_M+=1"
if %__ES_M% LEQ 12 exit /b 0
set /a "__ES_M=1, __ES_Y+=1"
exit /b 0
:es_day_prev
set /a "__ES_D-=1"
if %__ES_D% GEQ 1 exit /b 0
set /a "__ES_M-=1"
if %__ES_M% LSS 1 set /a "__ES_M=12, __ES_Y-=1"
call :es_dim
set /a "__ES_D=__ES_DIM"
exit /b 0
:es_dim
set /a "__ES_DIM=31"
for %%m in (4 6 9 11) do if %__ES_M%==%%m set /a "__ES_DIM=30"
if %__ES_M%==2 set /a "__ES_DIM=28+!(__ES_Y %% 4)-!(__ES_Y %% 100)+!(__ES_Y %% 400)"
exit /b 0

:es_digit_groups
rem __ES_G1 to __ES_G4 (the first four) and __ES_GL (the last): the runs of digits in the first 64
rem characters of the variable named by the argument (date and time are dynamic, so !date! is
rem read); every other character separates them, so the text is never %expanded%.
for %%V in (G1 G2 G3 G4 GL) do set "__ES_%%V="
setlocal EnableDelayedExpansion
set "__ES_X=!%~1!"
set "__ES_Y="
for /l %%i in (0,1,63) do if defined __ES_X (
    set "__ES_C=!__ES_X:~0,1!"
    set "__ES_X=!__ES_X:~1!"
    set "__ES_D= "
    for %%d in (0 1 2 3 4 5 6 7 8 9) do if "!__ES_C!"=="%%d" set "__ES_D=%%d"
    set "__ES_Y=!__ES_Y!!__ES_D!"
)
set "__ES_L="
for %%g in (!__ES_Y!) do set "__ES_L=%%g"
if not defined __ES_L exit /b 0
for /f "tokens=1-4" %%a in ("!__ES_Y!") do (endlocal & set "__ES_G1=%%a" & set "__ES_G2=%%b" & set "__ES_G3=%%c" & set "__ES_G4=%%d" & set "__ES_GL=%__ES_L%")
exit /b 0

:es_codepage
rem __ES_CP: the console code page, the last number chcp.com prints (its text is localized and
rem the colon may be a full-width one).
set "__ES_CPL="
"%__ES_SYS%\chcp.com" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do set "__ES_CPL=%%L"
call :es_digit_groups __ES_CPL
set "__ES_CP=%__ES_GL%"
exit /b 0
