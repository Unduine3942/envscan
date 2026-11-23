rem ## envscan.cmd part 00-launcher: entry point, argument parser and usage, 64-bit relaunch and
rem ## PowerShell launch, temporary files, checks for values from outside, PowerShell lookup and
rem ## execution-policy prediction. tools/target_cmd.py joins src/cmd/NN-*.cmd in name order
rem ## without these lines.
@echo off
rem envscan.cmd - Windows launcher for envscan.ps1 with a reduced cmd.exe-only fallback collector.
rem Generated from src/cmd/NN-*.cmd by tools/build.py; edit the sources, never dist/.
rem Read-only: the only writes are the output folder and self-deleting temporary files.
rem Variables named __ES_* belong to this script and are removed before PowerShell starts.
rem Values from the environment, the registry, files and arguments are read with !expansion! and
rem checked (:es_env_path, :es_env_word, :es_arg_ok) before any %expansion%: a quote in a value
rem that is %expanded% ends the quoted string, and the rest of the value would run as commands.
rem Programs write to a capture file that FOR /F reads: FOR /F ('command') would start a cmd.exe
rem child that runs the AutoRun commands of the registry (only the *_child labels still do, when
rem no capture file can be made).
setlocal EnableExtensions DisableDelayedExpansion
rem CD, ERRORLEVEL, RANDOM, ... are dynamic unless a variable of that name exists; such variables
rem are removed (PowerShell does not use them). __ES_RELAUNCHED counts only as exactly 1. The
rem caller's other __ES_* variables are removed just before PowerShell starts (listing them needs
rem the capture file) and cleared by :es_init and :es_clear_inherited for this script.
for %%V in (CD ERRORLEVEL RANDOM CMDCMDLINE CMDEXTVERSION HIGHESTNUMANODENUMBER) do set "%%V="
setlocal EnableDelayedExpansion
set "__ES_R=0"
if "!__ES_RELAUNCHED!"=="1" set "__ES_R=1"
endlocal & set "__ES_R=%__ES_R%"
for %%R in (%__ES_R%) do (
    set "__ES_R="
    set "__ES_RELAUNCHED="
    setlocal
    set "__ES_WAS_RELAUNCHED="
    if "%%R"=="1" set "__ES_WAS_RELAUNCHED=1"
)
goto :es_main

:es_main
call :es_init
call :es_where
call :es_temp_files
goto :es_parse_next
:es_main_parsed
if defined __ES_OPT_WSH call :es_wsh_check_args
if defined __ES_BADARG goto :es_fallback_badarg
if defined __ES_OPT_HELP (call :es_cleanup_temp & call :es_usage & exit /b 0)
if defined __ES_WAS_RELAUNCHED goto :es_main_run
if not defined PROCESSOR_ARCHITEW6432 goto :es_main_run
if not exist "%__ES_WIN%\Sysnative\cmd.exe" goto :es_main_run
rem 32-bit cmd.exe on 64-bit Windows: run again in the 64-bit cmd.exe (native registry view) with
rem the checked arguments, every value in quotes; the outer quotes are escaped. The new cmd.exe
rem expands its command line once more: no value holds a percent sign (see :es_out_ok), and the
rem script path is passed as the name of __ES_RL_SELF, which it expands once, so a percent sign in
rem a folder name stays as it is.
call :es_cleanup_temp
set "__ES_RELAUNCHED=1"
set "__ES_RL_SELF=%__ES_SELF%"
"%__ES_WIN%\Sysnative\cmd.exe" /d /v:off /c ^""%%__ES_RL_SELF%%"%__ES_CMDARGS%^"
exit /b %errorlevel%
:es_main_run
if defined __ES_OPT_FALLBACK (set "__ES_KIND=forced" & goto :es_fallback)
call :es_find_powershell
if not defined __ES_PS (set "__ES_KIND=missing" & goto :es_try_wsh)
if not exist "%__ES_PS1%" (set "__ES_KIND=noscript" & goto :es_try_wsh)
call :es_predict_policy
if defined __ES_PS_BLOCKED (set "__ES_KIND=blocked" & goto :es_try_wsh)
if defined __ES_POL_BLOCK (set "__ES_KIND=policy" & goto :es_try_wsh)
if not defined __ES_ERR call :es_policy_unverifiable
if defined __ES_POL_BLOCK (set "__ES_KIND=policy" & goto :es_try_wsh)
rem endlocal first: PowerShell must see the caller's environment, not this script's variables.
rem Set after endlocal, inside the setlocal at the top (the caller's session keeps its own):
rem POWERSHELL_TELEMETRY_OPTOUT=1 and POWERSHELL_UPDATECHECK=Off (pwsh contacts Microsoft at
rem startup otherwise), TMP when the caller's is too long (see :es_safe_tmp), and the checked
rem SystemRoot and SystemDrive (endlocal restores the caller's, which :es_sysroot may have refused).
rem PowerShell gets the checked arguments (__ES_FWD), never the command line as given. What was
rem parsed is carried to :es_after_ps in __ES_SV_*, set only after PowerShell ended (the values
rem hold no quote); "call" never sees the arguments, so ^ and % in them stay unchanged.
if not defined __ES_CAP goto :es_launch_child
endlocal & set "__ES_CAP=%__ES_CAP%" & call :es_clear_inherited all & (if not "%__ES_TMPFIX%"=="" set "TMP=%__ES_TMPFIX%") & set "SystemRoot=%__ES_WIN%" & set "SystemDrive=%__ES_SYSDRIVE%" & set "POWERSHELL_TELEMETRY_OPTOUT=1" & set "POWERSHELL_UPDATECHECK=Off" & "%__ES_PS%" -NoProfile -NonInteractive -File "%__ES_PS1%"%__ES_FWD% <nul 2>"%__ES_ERR%" & call set "__ES_PS_RC=%%errorlevel%%" & set "__ES_SV_ERR=%__ES_ERR%" & set "__ES_SV_CAP=%__ES_CAP%" & set "__ES_SV_REL=%__ES_WAS_RELAUNCHED%" & set "__ES_SV_OUT=%__ES_OPT_OUT%" & set "__ES_SV_ONLY=%__ES_OPT_ONLY%" & set "__ES_SV_SKIP=%__ES_OPT_SKIP%" & set "__ES_SV_LIST=%__ES_OPT_LIST%" & set "__ES_SV_VER=%__ES_OPT_VERSION%" & set "__ES_SV_IGN=%__ES_IGNORED%" & set "__ES_SV_WSH=%__ES_OPT_WSH%" & call :es_after_ps
exit /b %errorlevel%
:es_launch_child
rem No capture file (no private temporary folder): a FOR /F child lists the caller's __ES_*
rem variables, and PowerShell's error output goes to the console.
endlocal & (if not "%__ES_TMPFIX%"=="" set "TMP=%__ES_TMPFIX%") & set "SystemRoot=%__ES_WIN%" & set "SystemDrive=%__ES_SYSDRIVE%" & set "POWERSHELL_TELEMETRY_OPTOUT=1" & set "POWERSHELL_UPDATECHECK=Off" & (for /f "delims==" %%V in ('set __ES_ 2^>nul') do if defined %%V for /f "delims=_" %%W in ("%%V") do if /i "%%W"=="ES" set "%%V=") & "%__ES_PS%" -NoProfile -NonInteractive -File "%__ES_PS1%"%__ES_FWD% <nul & call set "__ES_PS_RC=%%errorlevel%%" & set "__ES_SV_ERR=" & set "__ES_SV_CAP=" & set "__ES_SV_REL=%__ES_WAS_RELAUNCHED%" & set "__ES_SV_OUT=%__ES_OPT_OUT%" & set "__ES_SV_ONLY=%__ES_OPT_ONLY%" & set "__ES_SV_SKIP=%__ES_OPT_SKIP%" & set "__ES_SV_LIST=%__ES_OPT_LIST%" & set "__ES_SV_VER=%__ES_OPT_VERSION%" & set "__ES_SV_IGN=%__ES_IGNORED%" & set "__ES_SV_WSH=%__ES_OPT_WSH%" & call :es_after_ps
exit /b %errorlevel%

:es_after_ps
rem Runs after PowerShell returned, outside the script's setlocal: __ES_PS_RC is its exit code. Its
rem own setlocal keeps the caller's environment for envscan.js (see :es_wsh_launch).
setlocal
call :es_restore
set /a "__ES_PS_RC=__ES_PS_RC" 2>nul
if "%__ES_PS_RC%"=="0" goto :es_ps_finish
if "%__ES_PS_RC%"=="2" goto :es_ps_finish
if "%__ES_PS_RC%"=="-1073741510" goto :es_ps_finish
if not "%__ES_PS_RC%"=="1" (set "__ES_KIND=failed" & goto :es_after_fallback)
if not defined __ES_ERR goto :es_ps_finish
"%__ES_SYS%\findstr.exe" /l /c:"UnauthorizedAccess" /c:"PSSecurityException" "%__ES_ERR%" >nul 2>nul || goto :es_ps_finish
set "__ES_KIND=refused"
:es_after_fallback
call :es_find_powershell
call :es_predict_policy
goto :es_try_wsh
:es_ps_finish
if defined __ES_ERR if exist "%__ES_ERR%" type "%__ES_ERR%" 1>&2
call :es_cleanup_temp
exit /b %__ES_PS_RC%

:es_init
set "__ES_VERSION=@@ES_VERSION@@"
call :es_sysroot
rem Children such as reg.exe get the checked Windows directory (PowerShell and cscript.exe get it
rem and the checked SystemDrive on their launch lines, after endlocal).
set "SystemRoot=%__ES_WIN%"
call :es_safe_tmp
set "__ES_PH=@@ES_REDACT_PLACEHOLDER@@"
set "__ES_RX_SEGMENTS=@@ES_REDACT_SEGMENTS@@"
set "__ES_RX_CONTAINS=@@ES_REDACT_CONTAINS@@"
set "__ES_RX_EXCEPT=@@ES_REDACT_EXCEPT@@"
set "__ES_RX_SUFFIXES=@@ES_REDACT_SUFFIXES@@"
set "__ES_RX_PREFIXES=@@ES_REDACT_PREFIXES@@"
set "__ES_RX_NSUFFIXES=@@ES_REDACT_NAME_SUFFIXES@@"
set "__ES_RX_PAIRS=@@ES_REDACT_PAIRS@@"
set "__ES_RX_OPTIONS=@@ES_REDACT_OPTIONS@@"
set "__ES_RX_HEADERS=@@ES_REDACT_HEADERS@@"
set "__ES_RX_TOOLOPTS=@@ES_REDACT_TOOL_OPTIONS@@"
set "__ES_RX_TOOLNAMES=@@ES_REDACT_TOOL_NAMES@@"
set "__ES_RX_TRIGGERS=@@ES_REDACT_TRIGGERS@@"
set /a "__ES_RX_MINLEN=@@ES_REDACT_MINLEN@@"
set "__ES_PROBES=@@ES_PROBE_IDS@@"
set "__ES_ALLIDS=@@ES_ALL_PROBE_IDS@@"
set "__ES_RC=0"
rem Numbers the argument captures from 1001: four digits for every argument a command line holds.
set "__ES_AN=1000"
rem The caller's copies are cleared: values used before they are set must be this script's own.
for %%V in (OPT_HELP OPT_FALLBACK OPT_WSH OPT_LIST OPT_VERSION OPT_OUT OPT_ONLY OPT_SKIP BADARG IGNORED KIND PS PS_KIND) do set "__ES_%%V="
for %%V in (PS_BLOCKED POL POL_SCOPE POL_GPO POL_BLOCK POL_WHY POL_UNREAD HOOK_NOTE ZONE SIGNED DOWNLOADED SUMMARY) do set "__ES_%%V="
for %%V in (ERR CAP CAP_OUT FWD CMDARGS JSFWD OUT_SLASH WSH_WHY WSH_RC WSH_NOTE WSH_IGN INH_DONE LOCALDRV PFN OUT_SKIPPED STAMP STAMP_UTC REG_DEAD REG_CHECKED LF CR) do set "__ES_%%V="
exit /b 0

:es_sysroot
rem __ES_WIN (Windows directory), __ES_SYS (its System32) and __ES_SYSDRIVE (X:) from SystemRoot,
rem windir and SystemDrive. They are %expanded% everywhere, unquoted in FOR /F commands too, so
rem only X:\ followed by letters, digits, . _ - \ is accepted, and only with a System32 folder;
rem else C:\Windows and its drive.
setlocal EnableDelayedExpansion
set "__ES_W="
for %%V in (SystemRoot windir) do if not defined __ES_W (
    set "__ES_X=!%%V!"
    if defined __ES_X if "!__ES_X:~1,2!"==":\" (
        set "__ES_Y=#!__ES_X:~0,1!!__ES_X:~3!"
        for %%c in (a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 . _ - \) do set "__ES_Y=!__ES_Y:%%c=!"
        if "!__ES_Y!"=="#" if exist "!__ES_X!\System32\" set "__ES_W=!__ES_X!"
    )
)
if not defined __ES_W set "__ES_W=C:\Windows"
if "!__ES_W:~-1!"=="\" set "__ES_W=!__ES_W:~0,-1!"
set "__ES_D=!__ES_W:~0,2!"
set "__ES_X=#!SystemDrive!"
if "!__ES_X:~2!"==":" for %%c in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do if /i "!__ES_X:~1,1!"=="%%c" set "__ES_D=!__ES_X:~1!"
endlocal & set "__ES_WIN=%__ES_W%" & set "__ES_SYS=%__ES_W%\System32" & set "__ES_SYSDRIVE=%__ES_D%"
exit /b 0

:es_safe_tmp
rem Windows answers "where are temporary files" with TMP, else TEMP, else USERPROFILE, made a
rem full path. Longer than MAX_PATH, every FOR /F command and Windows PowerShell spin forever:
rem then this script (and PowerShell, see :es_main_run) use a short folder as TMP instead, the
rem caller's TEMP or LOCALAPPDATA\Temp when usable, else the Windows Temp folder. __ES_TMPFIX
rem holds it; the caller's session keeps its own TMP.
set "__ES_TMPFIX="
setlocal EnableDelayedExpansion
set "__ES_X="
for %%V in (TMP TEMP USERPROFILE) do if not defined __ES_X if defined %%V set "__ES_X=!%%V!"
if not defined __ES_X (endlocal & exit /b 0)
set "__ES_Y=!__ES_X:~1,2!"
if not "!__ES_Y!"==":\" if not "!__ES_X:~0,2!"=="\\" set "__ES_X=!CD!\!__ES_X!"
if "!__ES_X:~240,1!"=="" (endlocal & exit /b 0)
endlocal
call :es_tmp_candidate TEMP
call :es_tmp_candidate LOCALAPPDATA \Temp
if not defined __ES_TMPFIX set "__ES_TMPFIX=%__ES_WIN%\Temp"
set "TMP=%__ES_TMPFIX%"
exit /b 0
:es_tmp_candidate
if defined __ES_TMPFIX exit /b 0
call :es_env_path %1 __ES_T || exit /b 1
set "__ES_T=%__ES_T%%~2"
if "%__ES_T:~-1%"=="\" set "__ES_T=%__ES_T:~0,-1%"
if not "%__ES_T:~1,2%"==":\" exit /b 1
if not "%__ES_T:~200,1%"=="" exit /b 1
if not exist "%__ES_T%\" exit /b 1
set "__ES_TMPFIX=%__ES_T%"
exit /b 0

:es_where
rem __ES_SELF and __ES_DIR (this script; inside a called label the path is right even when the
rem script was found on PATH, at the top it would name the working directory), __ES_PS1,
rem __ES_CWD (working directory, CD is dynamic, see the top) and __ES_CWD_NOTE. cmd.exe cannot
rem work in a UNC folder and switches to the Windows directory, so a script on a UNC path that
rem finds itself there was most likely started from its own folder; that folder is reported but
rem never written to (a network location).
set "__ES_SELF=%~f0"
set "__ES_DIR=%~dp0"
set "__ES_PS1=%__ES_DIR%envscan.ps1"
set "__ES_CWD=%CD%"
set "__ES_CWD_NOTE="
if not "%__ES_DIR:~0,2%"=="\\" exit /b 0
for %%W in ("%__ES_WIN%" "%__ES_SYS%") do if /i "%__ES_CWD%"=="%%~W" set "__ES_CWD_NOTE=cmd.exe cannot use the UNC folder of envscan.cmd as working directory and switched to %%~W"
exit /b 0

rem ---------------------------------------------------------------- arguments
:es_parse_next
rem :es_arg_read reads the first argument (each next one after a shift) and jumps back to the
rem label in __ES_RET with __ES_ARG (1 when there is an argument, "" counts) and __ES_A (its
rem value without the quotes around it). cmd.exe splits arguments at , ; = as well as spaces.
set "__ES_RET=es_parse_arg"
goto :es_arg_read
:es_parse_arg
if not defined __ES_ARG goto :es_main_parsed
if defined __ES_A goto :es_parse_option
if not defined __ES_BADARG set "__ES_BADARG=an argument is empty"
goto :es_parse_shift
:es_parse_option
set "__ES_K="
if "%__ES_A:~0,1%"=="-" set "__ES_K=%__ES_A:~1%"
if "%__ES_A:~0,2%"=="--" set "__ES_K=%__ES_A:~2%"
if "%__ES_A%"=="/?" set "__ES_K=?"
if not defined __ES_K goto :es_parse_bad
set "__ES_FLAG="
if /i "%__ES_K%"=="help" set "__ES_FLAG=--help"
if /i "%__ES_K%"=="h" set "__ES_FLAG=--help"
if "%__ES_K%"=="?" set "__ES_FLAG=--help"
if defined __ES_FLAG (set "__ES_OPT_HELP=1" & goto :es_parse_flag)
if /i "%__ES_K%"=="fallback" (set "__ES_OPT_FALLBACK=1" & set "__ES_FLAG=--fallback" & call :es_fwd_add --fallback "" cmd & goto :es_parse_flag)
if /i "%__ES_K%"=="wsh" (set "__ES_OPT_WSH=1" & set "__ES_FLAG=--wsh" & call :es_fwd_add --wsh "" cmd & goto :es_parse_flag)
if /i "%__ES_K%"=="list-probes" (set "__ES_OPT_LIST=1" & set "__ES_FLAG=--list-probes" & call :es_fwd_add --list-probes & goto :es_parse_flag)
if /i "%__ES_K%"=="version" (set "__ES_OPT_VERSION=1" & set "__ES_FLAG=--version" & call :es_fwd_add --version & goto :es_parse_flag)
for %%F in (deep net no-redact) do if /i "%__ES_K%"=="%%F" (set "__ES_FLAG=--%%F" & set "__ES_IGNORED=%__ES_IGNORED% --%%F" & call :es_fwd_add --%%F & goto :es_parse_flag)
for %%F in (out timeout budget) do if /i "%__ES_K%"=="%%F" (set "__ES_FLAG=--%%F" & goto :es_parse_value)
if /i "%__ES_K%"=="only" (set "__ES_LV=__ES_OPT_ONLY" & set "__ES_FLAG=--only" & goto :es_parse_list)
if /i "%__ES_K%"=="skip" (set "__ES_LV=__ES_OPT_SKIP" & set "__ES_FLAG=--skip" & goto :es_parse_list)
:es_parse_bad
if not defined __ES_BADARG set "__ES_BADARG=unknown argument: %__ES_A%"
goto :es_parse_shift
:es_parse_flag
rem A flag takes no value. cmd.exe splits --deep=0 into --deep and 0: an argument after a flag
rem that is not an option is an error, never a silently enabled flag.
shift
set "__ES_RET=es_parse_flag_next"
goto :es_arg_read
:es_parse_flag_next
if not defined __ES_ARG goto :es_main_parsed
if not defined __ES_A goto :es_parse_arg
if "%__ES_A:~0,1%"=="-" goto :es_parse_arg
if "%__ES_A:~0,1%"=="/" goto :es_parse_arg
if not defined __ES_BADARG set "__ES_BADARG=option %__ES_FLAG% takes no value"
goto :es_parse_shift
:es_parse_value
rem --out, --timeout and --budget take the next argument as their value.
shift
set "__ES_RET=es_parse_value_read"
goto :es_arg_read
:es_parse_value_read
if defined __ES_A goto :es_parse_value_%__ES_FLAG:~2%
set "__ES_X=a value"
if "%__ES_FLAG%"=="--out" set "__ES_X=a directory"
if not defined __ES_BADARG set "__ES_BADARG=%__ES_FLAG% needs %__ES_X%"
if not defined __ES_ARG goto :es_main_parsed
goto :es_parse_shift
:es_parse_value_out
call :es_out_ok || (if not defined __ES_BADARG set "__ES_BADARG=--out needs a directory path without quotes or %% < > | * ?")
rem Every --out is forwarded, not only the last: any one that starts with // is remembered for
rem :es_wsh_check_args, whether --wsh comes before or after it.
if defined __ES_OPT_OUT if "%__ES_OPT_OUT:~0,2%"=="//" set "__ES_OUT_SLASH=1"
call :es_fwd_add --out __ES_OPT_OUT
goto :es_parse_shift
:es_parse_value_timeout
:es_parse_value_budget
call :es_isnum __ES_A || (if not defined __ES_BADARG set "__ES_BADARG=%__ES_FLAG% needs a number of seconds")
set "__ES_IGNORED=%__ES_IGNORED% %__ES_FLAG% %__ES_A%"
call :es_fwd_add %__ES_FLAG% __ES_A
goto :es_parse_shift
:es_parse_list
rem --only a,b arrives as --only a b: every following argument that is not an option is a
rem pattern. They are joined with commas and checked by :es_check_patterns.
set "__ES_LIST="
:es_parse_list_next
shift
set "__ES_RET=es_parse_list_item"
goto :es_arg_read
:es_parse_list_item
if not defined __ES_A goto :es_parse_list_end
if "%__ES_A:~0,1%"=="-" goto :es_parse_list_end
if "%__ES_A:~0,1%"=="/" goto :es_parse_list_end
set "__ES_LIST=%__ES_LIST%,%__ES_A%"
goto :es_parse_list_next
:es_parse_list_end
if defined __ES_LIST goto :es_parse_list_check
if not defined __ES_BADARG set "__ES_BADARG=%__ES_FLAG% needs probe ids"
goto :es_parse_arg
:es_parse_list_check
set "%__ES_LV%=%__ES_LIST:~1%"
set "__ES_REST=%__ES_LIST%"
call :es_check_patterns %__ES_FLAG%
call :es_fwd_add %__ES_FLAG% %__ES_LV%
goto :es_parse_arg
:es_parse_shift
shift
goto :es_parse_next
:es_parse_quote
if errorlevel 2 (set "__ES_BADARG=an argument could not be read") else set "__ES_BADARG=an argument contains a quote character"
goto :es_main_parsed
:es_arg_read
rem The argument is captured as cmd.exe split it, quotes and all: with echo on cmd.exe writes the
rem REM command to the capture file, and REM runs nothing whatever quotes or & | < > ^ the
rem argument holds. Only when :es_arg_ok finds no quote inside it is the value read without its
rem quotes (inside quotes, a quote in it would end the string and run the rest). The number in
rem the line (__ES_AN) tells the line of this argument from one an earlier capture left.
set "__ES_ARG="
set "__ES_A="
if not defined __ES_CAP goto :es_arg_read_plain
set /a "__ES_AN+=1"
setlocal
set "prompt=#"
(
    echo on
    @for %%a in (1) do rem %__ES_AN%#%1#
) >"%__ES_CAP%"
@echo off
endlocal
call :es_arg_ok
if errorlevel 3 goto :es_arg_help
if errorlevel 1 goto :es_parse_quote
if not defined __ES_ARG goto :%__ES_RET%
set "__ES_A=%~1"
goto :%__ES_RET%
:es_arg_help
rem REM printed its own help instead of the line: the argument holds a slash followed by a
rem question mark, a help request as --help is (the help text is localized and never read).
set "__ES_ARG=1"
set "__ES_A=/?"
goto :%__ES_RET%
:es_arg_read_plain
rem No capture file (no private temporary folder): the value is read directly and refused when it
rem holds a quote, as before the capture existed; an empty "" is told from the end by the next one.
set "__ES_A=%~1"
if defined __ES_A goto :es_arg_read_plain_ok
set "__ES_A=%~2"
if defined __ES_A set "__ES_ARG=1"
set "__ES_A="
goto :%__ES_RET%
:es_arg_read_plain_ok
set "__ES_ARG=1"
call :es_no_quote __ES_A || goto :es_parse_quote
goto :%__ES_RET%

rem ---------------------------------------------------------------- checks for values from outside
:es_arg_ok
rem The captured "#rem <number>#<argument># " line: exit code 0 when the argument holds no quote
rem or one pair around all of it (__ES_ARG=1; unset when there is no argument), 1 when it holds
rem another quote (one inside, or one never closed), 2 when the capture cannot be read or holds
rem the line of an earlier argument, 3 when it holds other text: the help REM prints for a slash
rem followed by a question mark in the argument.
set "__ES_L="
for /f "usebackq delims=" %%L in ("%__ES_CAP%") do set "__ES_L=%%L"
setlocal EnableDelayedExpansion
if not defined __ES_L exit /b 2
if not "!__ES_L:~0,10!"=="#rem !__ES_AN!#" (if "!__ES_L:~0,5!"=="#rem " (exit /b 2) else exit /b 3)
set "__ES_X=!__ES_L:~10!"
if not defined __ES_X exit /b 2
if "!__ES_X:~-2!"=="# " (set "__ES_X=!__ES_X:~0,-2!") else if "!__ES_X:~-1!"=="#" (set "__ES_X=!__ES_X:~0,-1!") else exit /b 2
if not defined __ES_X (endlocal & exit /b 0)
set "__ES_Y=!__ES_X:"=!"
if "!__ES_Y!"=="!__ES_X!" (endlocal & set "__ES_ARG=1" & exit /b 0)
if "!__ES_X!"==""!__ES_Y!"" (endlocal & set "__ES_ARG=1" & exit /b 0)
exit /b 1

:es_no_quote
rem Exit code 1 when the variable named by the argument holds a quote character.
setlocal EnableDelayedExpansion
set "__ES_Y=!%~1:"=!"
if "!__ES_Y!"=="!%~1!" exit /b 0
exit /b 1

:es_env_path
rem Copies the variable named by the first argument into the one named by the second when it is
rem a path that is safe to %expand% inside quotes: no quote and none of < > | * ? (characters a
rem Windows path cannot hold). Else the second one is cleared and the exit code is 1.
setlocal EnableDelayedExpansion
set "__ES_X=!%~1!"
if not defined __ES_X (endlocal & set "%~2=" & exit /b 1)
rem (No FOR list for the characters: FOR would treat ? and * as file name wildcards.)
set "__ES_Y=!__ES_X:"=!"
if not "!__ES_Y!"=="!__ES_X!" (endlocal & set "%~2=" & exit /b 1)
if not "!__ES_X:<=!"=="!__ES_X!" (endlocal & set "%~2=" & exit /b 1)
if not "!__ES_X:>=!"=="!__ES_X!" (endlocal & set "%~2=" & exit /b 1)
if not "!__ES_X:|=!"=="!__ES_X!" (endlocal & set "%~2=" & exit /b 1)
if not "!__ES_X:?=!"=="!__ES_X!" (endlocal & set "%~2=" & exit /b 1)
if not "!__ES_X!"=="!__ES_X:**=!" (endlocal & set "%~2=" & exit /b 1)
for /f "eol=| delims=" %%v in ("!__ES_X!") do (endlocal & set "%~2=%%v")
exit /b 0

:es_out_ok
rem --out (__ES_A, copied into __ES_OPT_OUT): a path for :es_env_path that holds no percent sign
rem either. A cmd.exe command line (the 64-bit relaunch) would expand it once more, so it is
rem refused on every path, whatever the bitness of cmd.exe.
setlocal EnableDelayedExpansion
if not "!__ES_A:%%=!"=="!__ES_A!" (endlocal & set "__ES_OPT_OUT=" & exit /b 1)
endlocal
call :es_env_path __ES_A __ES_OPT_OUT || exit /b 1
exit /b 0

:es_env_word
rem Copies the variable named by the first argument into the one named by the second when it
rem holds only letters, digits, . _ and -; else the second one is cleared (exit code 1).
setlocal EnableDelayedExpansion
set "__ES_X=!%~1!"
if not defined __ES_X (endlocal & set "%~2=" & exit /b 1)
for /f "eol=. delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" %%x in ("a!__ES_X!") do (endlocal & set "%~2=" & exit /b 1)
endlocal & set "%~2=%__ES_X%"
exit /b 0

:es_var_is
rem Exit code 0 when the variable named by the first argument equals the second (ignoring case).
setlocal EnableDelayedExpansion
if /i "!%~1!"=="%~2" exit /b 0
exit /b 1

:es_fwd_add
rem Appends the option in the first argument and the value of the variable named by the second
rem (when one is named) to __ES_CMDARGS (the arguments of the 64-bit relaunch, the value in
rem quotes) and, unless the third argument is cmd, to __ES_FWD (PowerShell's arguments, where a
rem run of backslashes before the closing quote is doubled: CommandLineToArgvW reads \" as a
rem quote) and __ES_JSFWD (envscan.js's arguments, quoted as in __ES_CMDARGS: WSH keeps \").
rem Values hold no quote. The strings start with a space and are never empty.
setlocal EnableDelayedExpansion
set "__ES_X=!__ES_FWD! %~1"
set "__ES_C=!__ES_CMDARGS! %~1"
set "__ES_J=!__ES_JSFWD! %~1"
if "%~2"=="" goto :es_fwd_add_end
set "__ES_Y=!%~2!"
set "__ES_C=!__ES_C! "!__ES_Y!""
set "__ES_J=!__ES_J! "!__ES_Y!""
set "__ES_Z="
:es_fwd_add_bs
if "!__ES_Y:~-1!"=="\" (set "__ES_Y=!__ES_Y:~0,-1!" & set "__ES_Z=!__ES_Z!\\" & goto :es_fwd_add_bs)
set "__ES_X=!__ES_X! "!__ES_Y!!__ES_Z!""
:es_fwd_add_end
if "%~3"=="cmd" goto :es_fwd_add_cmd
for /f "eol=| delims=" %%v in ("!__ES_X!") do for /f "eol=| delims=" %%c in ("!__ES_C!") do for /f "eol=| delims=" %%j in ("!__ES_J!") do (endlocal & set "__ES_FWD=%%v" & set "__ES_CMDARGS=%%c" & set "__ES_JSFWD=%%j")
exit /b 0
:es_fwd_add_cmd
for /f "eol=| delims=" %%c in ("!__ES_C!") do (endlocal & set "__ES_CMDARGS=%%c")
exit /b 0

:es_usage
echo envscan @@ES_VERSION@@ - environment scanner launcher
echo.
echo Usage: envscan.cmd [options]
echo.
echo Runs envscan.ps1 from this folder with Windows PowerShell:
echo   powershell.exe -NoProfile -NonInteractive -File envscan.ps1 [options]
echo The execution policy is respected and never changed. If PowerShell is missing or blocked,
echo or its policy does not allow the script, a reduced cmd.exe-only collector runs instead
echo and explains how the full scan can be run.
echo.
echo Options of envscan.cmd:
echo   --fallback      run only the reduced cmd.exe collector; PowerShell is not started
echo   --wsh           when PowerShell or envscan.ps1 is missing or a local execution policy
echo                   blocks the script: run envscan.js with cscript.exe before the collector
echo   --help          this text
echo The other options are checked, then passed on to envscan.ps1:
echo   --deep  --net  --out DIR  --only IDS  --skip IDS  --timeout SEC  --budget SEC
echo   --no-redact  --list-probes  --version
echo An argument with a quote character inside it, or one that is never closed, is refused.
echo The fallback collector honours --out, --only, --skip, --list-probes and --version; it
echo records and ignores the others and always redacts.
echo.
echo Output: a folder envscan-HOST-UTCTIME under --out, else the current directory, else the
echo user profile, else TEMP. Network locations, Desktop, Documents, OneDrive folders and the
echo Windows directory are skipped; --out is used as given. The folder's path is the last line
echo on stdout. PowerShell's error output and the output of the programs envscan.cmd runs are
echo held in two files in your TEMP folder (or, for the fallback without one, in the output
echo folder) and deleted before envscan.cmd ends.
echo Exit codes: 0 complete, 1 some checks incomplete, 2 fatal (bad arguments, no output folder).
exit /b 0

rem ---------------------------------------------------------------- temporary files
:es_temp_files
rem __ES_ERR (PowerShell's error output) and __ES_CAP (the output of programs, which FOR /F reads
rem back) are new files in the user's own temporary folder: under the profile or LOCALAPPDATA, on
rem a local drive, never under the Windows directory. The names hold the time and two RANDOM
rem numbers. Without such a folder both stay unset (see :es_arg_read_plain, :es_launch_child,
rem :es_capture_in_output). A folder on the system drive is taken first: whether another drive
rem is local needs the list of local volumes, and without a capture file that list comes from
rem FOR /F children (see :es_local_drives).
set "__ES_ERR="
set "__ES_CAP="
call :es_env_path USERPROFILE __ES_UP
call :es_env_path LOCALAPPDATA __ES_LA
for %%D in (system any) do (
    set "__ES_TDRV=%%D"
    for %%N in (TEMP TMP) do if not defined __ES_CAP call :es_temp_try %%N
    if not defined __ES_CAP call :es_temp_try LOCALAPPDATA \Temp
)
set "__ES_TDRV="
exit /b 0
:es_temp_try
call :es_env_path %1 __ES_T || exit /b 1
set "__ES_T=%__ES_T%%~2"
if "%__ES_T:~-1%"=="\" set "__ES_T=%__ES_T:~0,-1%"
if not "%__ES_T:~1,2%"==":\" exit /b 1
call :es_is_under __ES_WIN && exit /b 1
set "__ES_OWN="
call :es_is_under __ES_UP && set "__ES_OWN=1"
call :es_is_under __ES_LA && set "__ES_OWN=1"
if not defined __ES_OWN exit /b 1
if /i not "%__ES_T:~0,2%"=="%__ES_SYSDRIVE%" (
    if "%__ES_TDRV%"=="system" exit /b 1
    if not defined __ES_LOCALDRV call :es_local_drives
    call :es_drive_is_local || exit /b 1
)
if not exist "%__ES_T%\" exit /b 1
call :es_time_digits
set "__ES_T=%__ES_T%\envscan-launch-%__ES_TDG%%RANDOM%%RANDOM%"
if exist "%__ES_T%.err" exit /b 1
if exist "%__ES_T%.out" exit /b 1
(type nul >"%__ES_T%.err") 2>nul || exit /b 1
(type nul >"%__ES_T%.out") 2>nul || (del /f /q "%__ES_T%.err" >nul 2>nul & exit /b 1)
set "__ES_ERR=%__ES_T%.err"
set "__ES_CAP=%__ES_T%.out"
exit /b 0
:es_time_digits
setlocal EnableDelayedExpansion
set "__ES_X=!time!"
set "__ES_Y="
for /l %%i in (0,1,15) do for %%d in (0 1 2 3 4 5 6 7 8 9) do if "!__ES_X:~%%i,1!"=="%%d" set "__ES_Y=!__ES_Y!%%d"
endlocal & set "__ES_TDG=%__ES_Y%"
exit /b 0

:es_cleanup_temp
rem Deletes the temporary files ("if not exist path\" rules out a folder of that name).
call :es_cleanup_err
if defined __ES_CAP if exist "%__ES_CAP%" if not exist "%__ES_CAP%\" del /f /q "%__ES_CAP%" >nul 2>nul
set "__ES_CAP="
exit /b 0
:es_cleanup_err
if defined __ES_ERR if exist "%__ES_ERR%" if not exist "%__ES_ERR%\" del /f /q "%__ES_ERR%" >nul 2>nul
set "__ES_ERR="
exit /b 0

:es_clear_inherited
rem The caller's __ES_* variables, as "set" lists them in the capture file. With "all" (just
rem before PowerShell starts, outside the script's setlocal) every one is removed; else only the
rem name families the fallback tests with "if defined" before it sets them. A line of a
rem multi-line value can look like a name: only names whose first part is ES are removed.
if not defined __ES_CAP exit /b 0
if "%~1"=="all" goto :es_clear_inherited_all
if defined __ES_INH_DONE exit /b 0
set "__ES_INH_DONE=1"
(set __ES_ >"%__ES_CAP%") 2>nul || exit /b 0
for /f "usebackq delims==" %%V in ("%__ES_CAP%") do if defined %%V for /f "tokens=1,2 delims=_" %%W in ("%%V") do if /i "%%W"=="ES" for %%F in (SEEN TID FEXE PRX) do if /i "%%X"=="%%F" set "%%V="
type nul >"%__ES_CAP%"
exit /b 0
:es_clear_inherited_all
(set __ES_ >"%__ES_CAP%") 2>nul || exit /b 0
(
    for /f "usebackq delims==" %%V in ("%__ES_CAP%") do if defined %%V for /f "delims=_" %%W in ("%%V") do if /i "%%W"=="ES" set "%%V="
    type nul >"%__ES_CAP%"
)
exit /b 0

rem ---------------------------------------------------------------- PowerShell and policy
:es_find_powershell
rem Windows PowerShell from System32; else pwsh.exe of %ProgramFiles%\PowerShell\N (the highest
rem release number), else from a local PATH folder; never the WindowsApps alias, which may only
rem open the Microsoft Store.
set "__ES_PS="
set "__ES_PS_KIND="
if exist "%__ES_SYS%\WindowsPowerShell\v1.0\powershell.exe" (
    set "__ES_PS=%__ES_SYS%\WindowsPowerShell\v1.0\powershell.exe"
    set "__ES_PS_KIND=windows"
    exit /b 0
)
call :es_env_path ProgramFiles __ES_T
rem A folder name made of digits only leaves "#" as the only token of FOR /F "delims=0123456789".
if defined __ES_T for /d %%D in ("%__ES_T%\PowerShell\*") do if exist "%%~fD\pwsh.exe" for /f "delims=0123456789" %%x in ("%%~nxD#") do if "%%x"=="#" set "__ES_PS=%%~fD\pwsh.exe"
if defined __ES_PS (set "__ES_PS_KIND=core" & exit /b 0)
set "__ES_CB=es_pwsh_path_dir"
call :es_path_split
if defined __ES_PS set "__ES_PS_KIND=core"
exit /b 0
:es_pwsh_path_dir
if defined __ES_PS exit /b 0
call :es_path_kind
if not defined __ES_E2 exit /b 0
if defined __ES_KIND_SKIP exit /b 0
if defined __ES_KIND_DUP exit /b 0
if not "%__ES_E2:\WindowsApps=%"=="%__ES_E2%" exit /b 0
if exist "%__ES_E2%\pwsh.exe" set "__ES_PS=%__ES_E2%\pwsh.exe"
exit /b 0

:es_predict_policy
rem Predicts what PowerShell would decide for envscan.ps1 without starting PowerShell. When
rem reg.exe cannot read the registry, no Group Policy setting can be ruled out: the policy stays
rem unknown, PowerShell is started and only its own refusal leads to the fallback.
for %%V in (PS_BLOCKED POL POL_SCOPE POL_GPO POL_BLOCK POL_WHY POL_UNREAD HOOK_NOTE ZONE SIGNED DOWNLOADED) do set "__ES_%%V="
if defined ENVSCAN_TEST_POLICY call :es_policy_hook
if defined __ES_POL_WHY exit /b 0
call :es_reg_check
if defined __ES_REG_DEAD (set "__ES_POL_UNREAD=1" & call :es_ps1_marks & exit /b 0)
set "__ES_POL_KEY=SOFTWARE\Policies\Microsoft\Windows\PowerShell"
if "%__ES_PS_KIND%"=="core" call :es_policy_core_key
call :es_policy_gpo HKLM MachinePolicy
if not defined __ES_POL call :es_policy_gpo HKCU UserPolicy
if not defined __ES_POL if defined PSExecutionPolicyPreference call :es_policy_process
if not defined __ES_POL if not "%__ES_PS_KIND%"=="core" call :es_policy_scope HKCU CurrentUser
if not defined __ES_POL if not "%__ES_PS_KIND%"=="core" call :es_policy_scope HKLM LocalMachine
if /i "%__ES_POL%"=="Default" set "__ES_POL="
if not defined __ES_POL call :es_policy_default
call :es_policy_decide
exit /b 0

:es_policy_name
rem The variable named by the argument keeps a PowerShell execution policy name (canonical case)
rem and is cleared otherwise, so a value from the registry or environment is never %expanded%.
setlocal EnableDelayedExpansion
set "__ES_Y="
for %%P in (AllSigned Bypass Default RemoteSigned Restricted Undefined Unrestricted) do if /i "!%~1!"=="%%P" set "__ES_Y=%%P"
endlocal & set "%~1=%__ES_Y%"
exit /b 0

:es_policy_hook
call :es_env_word ENVSCAN_TEST_POLICY __ES_X
if /i "%__ES_X%"=="allowed" (
    set "__ES_POL=Unrestricted"
    set "__ES_POL_SCOPE=test hook"
    set "__ES_POL_WHY=execution policy decision forced to allowed by ENVSCAN_TEST_POLICY"
    exit /b 0
)
if /i "%__ES_X%"=="restricted" (
    set "__ES_POL=Restricted"
    set "__ES_POL_SCOPE=LocalMachine"
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is Restricted, scope LocalMachine, which runs no scripts - simulated by ENVSCAN_TEST_POLICY=restricted"
    exit /b 0
)
if /i "%__ES_X%"=="allsigned-gpo" (
    set "__ES_POL=AllSigned"
    set "__ES_POL_SCOPE=MachinePolicy"
    set "__ES_POL_GPO=1"
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is AllSigned, scope MachinePolicy, and envscan.ps1 is not signed - simulated by ENVSCAN_TEST_POLICY=allsigned-gpo"
    exit /b 0
)
if /i "%__ES_X%"=="blocked" (
    set "__ES_PS_BLOCKED=1"
    set "__ES_POL_WHY=PowerShell could not be started - simulated by ENVSCAN_TEST_POLICY=blocked"
    exit /b 0
)
set "__ES_HOOK_NOTE=ENVSCAN_TEST_POLICY is not one of allowed, restricted, allsigned-gpo, blocked and was ignored"
exit /b 0

:es_policy_core_key
call :es_reg_get "HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore" UseWindowsPowerShellPolicySetting __ES_T1
set /a "__ES_X=-1"
if defined __ES_T1 set /a "__ES_X=__ES_T1" >nul 2>nul
if "%__ES_X%"=="1" exit /b 0
set "__ES_POL_KEY=SOFTWARE\Policies\Microsoft\PowerShellCore"
exit /b 0

:es_policy_gpo
rem EnableScripts 0 is Restricted; with 1 the ExecutionPolicy value decides. A missing, unknown or
rem Undefined value leaves the decision to the next scope, as PowerShell does.
call :es_reg_load "%~1\%__ES_POL_KEY%" "EnableScripts ExecutionPolicy"
if not defined __ES_RV_EnableScripts exit /b 0
set /a "__ES_X=-1"
set /a "__ES_X=__ES_RV_EnableScripts" >nul 2>nul
if "%__ES_X%"=="0" (set "__ES_POL=Restricted" & set "__ES_POL_SCOPE=%~2" & set "__ES_POL_GPO=1" & exit /b 0)
if not "%__ES_X%"=="1" exit /b 0
call :es_policy_name __ES_RV_ExecutionPolicy
if not defined __ES_RV_ExecutionPolicy exit /b 0
if "%__ES_RV_ExecutionPolicy%"=="Undefined" exit /b 0
set "__ES_POL=%__ES_RV_ExecutionPolicy%"
set "__ES_POL_SCOPE=%~2"
set "__ES_POL_GPO=1"
exit /b 0

:es_policy_process
call :es_env_word PSExecutionPolicyPreference __ES_T2
call :es_policy_name __ES_T2
if not defined __ES_T2 exit /b 0
if "%__ES_T2%"=="Undefined" exit /b 0
set "__ES_POL=%__ES_T2%"
set "__ES_POL_SCOPE=Process"
exit /b 0

:es_policy_scope
call :es_reg_get "%~1\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" ExecutionPolicy __ES_T2
call :es_policy_name __ES_T2
if not defined __ES_T2 exit /b 0
if "%__ES_T2%"=="Undefined" exit /b 0
set "__ES_POL=%__ES_T2%"
set "__ES_POL_SCOPE=%~2"
exit /b 0

:es_policy_default
if "%__ES_PS_KIND%"=="core" (set "__ES_POL=RemoteSigned" & set "__ES_POL_SCOPE=default of PowerShell 7" & exit /b 0)
set "__ES_POL=Restricted"
set "__ES_POL_SCOPE=default of Windows client"
call :es_reg_load "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "InstallationType CurrentBuild"
if not defined __ES_RV_InstallationType exit /b 0
if not defined __ES_RV_CurrentBuild exit /b 0
setlocal EnableDelayedExpansion
if /i not "!__ES_RV_InstallationType:~0,6!"=="Server" exit /b 0
endlocal
set /a "__ES_X=0"
set /a "__ES_X=__ES_RV_CurrentBuild" >nul 2>nul
if %__ES_X% LSS 9600 (set "__ES_POL_SCOPE=default of Windows Server" & exit /b 0)
set "__ES_POL=RemoteSigned"
set "__ES_POL_SCOPE=default of Windows Server"
exit /b 0

:es_policy_decide
call :es_ps1_marks
if /i "%__ES_POL%"=="Restricted" (
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is Restricted, scope %__ES_POL_SCOPE%, which runs no scripts"
    exit /b 0
)
if /i "%__ES_POL%"=="AllSigned" if not defined __ES_SIGNED (
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is AllSigned, scope %__ES_POL_SCOPE%, and envscan.ps1 is not signed"
    exit /b 0
)
if not defined __ES_DOWNLOADED exit /b 0
if defined __ES_SIGNED exit /b 0
if /i "%__ES_POL%"=="RemoteSigned" (
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is RemoteSigned, scope %__ES_POL_SCOPE%, and envscan.ps1 is marked as downloaded, zone %__ES_ZONE%, and not signed"
    exit /b 0
)
if /i "%__ES_POL%"=="Unrestricted" (
    set "__ES_POL_BLOCK=1"
    set "__ES_POL_WHY=the PowerShell execution policy is Unrestricted, scope %__ES_POL_SCOPE%, but PowerShell asks before it runs a downloaded script, zone %__ES_ZONE%, and the scan never prompts"
)
exit /b 0

:es_policy_unverifiable
rem Without a file for PowerShell's error output a refusal cannot be told from the scan's own exit
rem code 1, so a decision that rests on the signature (cmd.exe cannot check it), or on a policy
rem that could not be read, counts as refused.
if defined __ES_POL_UNREAD goto :es_policy_unverifiable_unread
if /i "%__ES_POL%"=="Restricted" goto :es_policy_unverifiable_set
if /i "%__ES_POL%"=="AllSigned" goto :es_policy_unverifiable_set
if defined __ES_DOWNLOADED if defined __ES_SIGNED goto :es_policy_unverifiable_set
exit /b 0
:es_policy_unverifiable_set
set "__ES_POL_BLOCK=1"
set "__ES_POL_WHY=the PowerShell execution policy is %__ES_POL%, scope %__ES_POL_SCOPE%; whether envscan.ps1 may run depends on its signature, which cmd.exe cannot check, and no temporary folder of yours is writable to detect a refusal"
exit /b 0
:es_policy_unverifiable_unread
set "__ES_POL_BLOCK=1"
set "__ES_POL_WHY=the PowerShell execution policy could not be read because reg.exe could not read the registry, and no temporary folder of yours is writable to detect a refusal"
exit /b 0

:es_ps1_marks
rem The Zone.Identifier stream belongs to whoever wrote the file: only its number is kept. A
rem failed input redirection runs nothing and leaves the output file as it was: it is emptied first.
set "__ES_ZONE="
set "__ES_SIGNED="
set "__ES_DOWNLOADED="
if not exist "%__ES_PS1%" exit /b 0
if not defined __ES_CAP goto :es_ps1_zone_child
(type nul >"%__ES_CAP%" & "%__ES_SYS%\findstr.exe" /b /i /c:"ZoneId=" <"%__ES_PS1%:Zone.Identifier" >"%__ES_CAP%") 2>nul
for /f "usebackq tokens=2 delims==" %%Z in ("%__ES_CAP%") do set "__ES_ZONE=%%Z"
goto :es_ps1_signature
:es_ps1_zone_child
(for /f "tokens=2 delims==" %%Z in ('%__ES_SYS%\findstr.exe /b /i /c:"ZoneId=" ^<"%__ES_PS1%:Zone.Identifier"') do set "__ES_ZONE=%%Z") 2>nul
:es_ps1_signature
set /a "__ES_X=0"
if defined __ES_ZONE set /a "__ES_X=__ES_ZONE" >nul 2>nul
if defined __ES_ZONE set "__ES_ZONE=%__ES_X%"
if %__ES_X% GEQ 3 set "__ES_DOWNLOADED=1"
"%__ES_SYS%\findstr.exe" /l /c:"# SIG # Begin signature block" "%__ES_PS1%" >nul 2>nul && set "__ES_SIGNED=1"
exit /b 0
