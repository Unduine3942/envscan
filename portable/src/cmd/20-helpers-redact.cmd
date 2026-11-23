rem ## envscan.cmd part 20-helpers-redact: registry and printing helpers, the env.vars probe and the
rem ## redaction rules of spec/redaction.toml. call and goto search the joined file forward from the
rem ## caller, so hot routines sit right after their callers: keep the order of routines and parts.

rem ---------------------------------------------------------------- helpers
:es_isnum
rem Exit code 0 when the variable named by the argument holds 1 to 9 digits, as envscan.ps1 and
rem envscan.sh accept (the leading 0 keeps a value that starts with ; from being skipped as a
rem comment by FOR /F).
setlocal EnableDelayedExpansion
set "__ES_X=!%~1!"
if not defined __ES_X exit /b 1
if not "!__ES_X:~9!"=="" exit /b 1
for /f "delims=0123456789" %%z in ("0!__ES_X!") do exit /b 1
exit /b 0

:es_reg_get
rem Reads one registry value into the variable named by the third argument (undefined when missing).
set "%~3="
set "__ES_REGTYPE="
if not defined __ES_CAP goto :es_reg_get_child
"%__ES_SYS%\reg.exe" query "%~1" /v "%~2" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1,2,*" %%A in ("%__ES_CAP%") do if /i "%%A"=="%~2" (set "%~3=%%C" & set "__ES_REGTYPE=%%B")
exit /b 0
:es_reg_get_child
for /f "tokens=1,2,*" %%A in ('%__ES_SYS%\reg.exe query "%~1" /v "%~2" 2^>nul') do if /i "%%A"=="%~2" (set "%~3=%%C" & set "__ES_REGTYPE=%%B")
exit /b 0

:es_reg_load
rem One reg.exe call for a whole key: sets __ES_RV_name (data) and __ES_RT_name (type) for each
rem value; the names in the second argument are cleared first so missing values read as undefined.
for %%N in (%~2) do (set "__ES_RV_%%N=" & set "__ES_RT_%%N=")
if not defined __ES_CAP goto :es_reg_load_child
"%__ES_SYS%\reg.exe" query "%~1" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1,2,*" %%A in ("%__ES_CAP%") do (set "__ES_RV_%%A=%%C" & set "__ES_RT_%%A=%%B")
exit /b 0
:es_reg_load_child
for /f "tokens=1,2,*" %%A in ('%__ES_SYS%\reg.exe query "%~1" 2^>nul') do (set "__ES_RV_%%A=%%C" & set "__ES_RT_%%A=%%B")
exit /b 0

:es_reg_check
rem __ES_REG_DEAD=1 when reg.exe cannot read a value every Windows has (reg.exe missing or blocked
rem by application control): registry values are then reported as not read, never as not set,
rem and the execution policy as unknown. (A key whose reading is denied looks like a missing one.)
if defined __ES_REG_CHECKED exit /b 0
set "__ES_REG_CHECKED=1"
call :es_reg_get "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentBuild __ES_T1
if not defined __ES_T1 set "__ES_REG_DEAD=1"
exit /b 0

:es_reg_values
rem Prints "<prefix><name>: <data>" for the value names in the third argument (one reg.exe call);
rem "not read" (and the probe partial) when reg.exe cannot read the registry.
if defined __ES_REG_DEAD if "%__ES_ST%"=="ok" set "__ES_ST=partial"
call :es_reg_load "%~1" "%~3"
set "__ES_RP=%~2"
setlocal EnableDelayedExpansion
set "__ES_NS=not set"
if defined __ES_REG_DEAD set "__ES_NS=not read"
for %%N in (%~3) do (
    if defined __ES_RT_%%N (
        set "__ES_V=!__ES_RV_%%N!"
        if /i "!__ES_RT_%%N!"=="REG_DWORD" (set /a "__ES_V=!__ES_V!") else if defined __ES_V call :es_redact_value
        echo(!__ES_RP!%%N: !__ES_V!
    ) else (
        echo(!__ES_RP!%%N: !__ES_NS!
    )
)
exit /b 0

:es_reg_show
rem Prints "label: data" for one registry value; DWORDs in decimal, strings redacted.
if defined __ES_REG_DEAD if "%__ES_ST%"=="ok" set "__ES_ST=partial"
call :es_reg_get "%~1" "%~2" __ES_V
set "__ES_L=%~3"
if not defined __ES_L set "__ES_L=%~2"
setlocal EnableDelayedExpansion
if not defined __ES_V if defined __ES_REG_DEAD (echo(!__ES_L!: not read& exit /b 0)
if not defined __ES_V (echo(!__ES_L!: not set& exit /b 0)
rem set /a must see the hex text itself: a variable name would saturate 0xfffffde4 at 2147483647.
if /i "!__ES_REGTYPE!"=="REG_DWORD" (set /a "__ES_V=!__ES_V!") else (call :es_redact_value)
echo(!__ES_L!: !__ES_V!
exit /b 0

:es_print_kv
rem Prints "label: value" (or only the value when the label is empty) without interpreting it.
setlocal EnableDelayedExpansion
set "__ES_L=%~1"
if defined __ES_L (echo(!__ES_L!: !%~2!) else (echo(!%~2!)
exit /b 0

:es_show_env
rem Prints NAME=value with redaction, or "NAME: not set".
if not defined %~1 (echo %~1: not set& exit /b 0)
setlocal EnableDelayedExpansion
set "__ES_N=%~1"
set "__ES_V=!%~1!"
goto :es_emit_nv

:es_emit_value
rem Prints __ES_PFX followed by the redacted __ES_V.
setlocal EnableDelayedExpansion
call :es_redact_value
echo(!__ES_PFX!!__ES_V!
exit /b 0

:es_probe_env_vars
rem "set" writes the lines of a multi-line value as lines of their own, and a value longer than
rem about 8000 characters without its line end (the next variable joins it). Only the text before
rem the first "=" of a line is used, as a name, and only when such a variable exists (once each);
rem its value is read from the environment, never from the line. The unredacted list is written
rem only to the private temporary folder, and emptied in the first pass of the loop: FOR /F has
rem read the whole file by then.
set "__ES_HIT=1"
set "__ES_ENLONG="
call :es_line_chars
if defined __ES_CAP_OUT goto :es_env_vars_child
set "__ES_EMPTIED="
set >"%__ES_CAP%" 2>nul
for /f "usebackq delims==" %%A in ("%__ES_CAP%") do (
    if not defined __ES_EMPTIED (set "__ES_EMPTIED=1" & type nul >"%__ES_CAP%")
    if defined %%A if not defined __ES_SEEN_ENV_%%A (set "__ES_SEEN_ENV_%%A=1" & set "__ES_N=%%A" & call :es_env_one || set "__ES_ENLONG=1")
)
type nul >"%__ES_CAP%"
goto :es_env_vars_notes
:es_env_vars_child
for /f "delims==" %%A in ('set 2^>nul') do if defined %%A if not defined __ES_SEEN_ENV_%%A (set "__ES_SEEN_ENV_%%A=1" & set "__ES_N=%%A" & call :es_env_one || set "__ES_ENLONG=1")
:es_env_vars_notes
echo note: names starting with __ES_ belong to envscan.cmd and are not listed
echo note: line breaks inside values are shown as ^<CR^> and ^<LF^>
if not defined __ES_ENLONG exit /b 0
set "__ES_ST=partial"
echo note: cmd.exe cannot read a value longer than about 8000 characters, and "set" joins the variable after such a value to it, so the variable after it in this list may be missing
exit /b 0
:es_env_one
rem __ES_N: a name from the output of "set". Exit code 1 when the variable exists but its value is
rem too long for cmd.exe to read.
setlocal EnableDelayedExpansion
if /i "!__ES_N:~0,5!"=="__ES_" exit /b 0
set "__ES_X=!__ES_N:"=!"
if not "!__ES_X!"=="!__ES_N!" exit /b 0
set "__ES_V="
for /f "eol=| delims=" %%K in ("!__ES_N!") do set "__ES_V=!%%K!"
if not defined __ES_V (echo(!__ES_N!: not shown, the value is longer than cmd.exe can read ^(about 8000 characters^)& exit /b 1)
for %%L in ("!__ES_LF!") do set "__ES_V=!__ES_V:%%~L=<LF> !"
if defined __ES_CR for %%C in ("!__ES_CR!") do set "__ES_V=!__ES_V:%%~C=<CR>!"
goto :es_emit_nv

:es_line_chars
rem __ES_LF: a line feed (the caret joins the empty line after it, whose line break remains).
rem __ES_CR: a carriage return, the first character "copy /z" writes (its progress line); kept
rem only when it is one character and no letter or digit.
if defined __ES_LF exit /b 0
set __ES_LF=^


set "__ES_CR="
copy /z "%__ES_SELF%" nul >"%__ES_CAP%" 2>nul
for /f "usebackq" %%a in ("%__ES_CAP%") do if not defined __ES_CR set "__ES_CR=%%a"
setlocal EnableDelayedExpansion
set "__ES_X=#!__ES_CR!"
if not "!__ES_X:~2!"=="" (endlocal & set "__ES_CR=" & exit /b 0)
for %%c in (a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9) do if /i "!__ES_X!"=="#%%c" (endlocal & set "__ES_CR=" & exit /b 0)
exit /b 0

:es_emit_nv
rem Reached by goto with delayed expansion on; prints __ES_N=__ES_V after the name rules of
rem spec/redaction.toml (a secret name keeps its name, its value becomes the placeholder) and
rem the value rules.
set "__ES_KN=!__ES_N!"
call :es_name_secret
if not errorlevel 1 (echo(!__ES_N!=!__ES_PH!& exit /b 0)
call :es_redact_value
echo(!__ES_N!=!__ES_V!
exit /b 0

:es_name_secret
rem Success when the name in __ES_KN is secret by the NAME RULES of spec/redaction.toml:
rem exceptions first, then segments, contains and name suffixes. Names with * ? or a quote
rem count as secret (a FOR list would expand or split them). Changes __ES_KN.
if not defined __ES_KN exit /b 1
for %%E in (%__ES_RX_EXCEPT%) do if /i "!__ES_KN!"=="%%E" exit /b 1
if not "!__ES_KN!"=="!__ES_KN:**=!" exit /b 0
if not "!__ES_KN!"=="!__ES_KN:?=!" exit /b 0
set "__ES_T=!__ES_KN:"=!"
if not "!__ES_T!"=="!__ES_KN!" exit /b 0
rem Upper-case copy (substitution ignores case, so replacing each letter by itself upper-cases
rem it); only names with lower-case letters can have camelCase boundaries.
set "__ES_KU=!__ES_KN!"
for %%U in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do set "__ES_KU=!__ES_KU:%%U=%%U!"
if not "!__ES_KU!"=="!__ES_KN!" call :es_camel
set "__ES_T=!__ES_KN!"
for %%c in (- . : / \ @ # $ + ' [ ] { } `) do set "__ES_T=!__ES_T:%%c=_!"
set "__ES_T=!__ES_T: =_!"
set "__ES_T=!__ES_T:;=_!"
set "__ES_T=!__ES_T:,=_!"
set "__ES_T=!__ES_T:(=_!"
set "__ES_T=!__ES_T:)=_!"
set "__ES_T=!__ES_T:&=_!"
set "__ES_T=!__ES_T:|=_!"
set "__ES_T=!__ES_T:<=_!"
set "__ES_T=!__ES_T:>=_!"
set "__ES_J=!__ES_T!#"
for %%S in (%__ES_RX_SUFFIXES%) do if /i not "!__ES_J:%%S#=!"=="!__ES_J!" exit /b 1
set "__ES_J=!__ES_T:_= !"
for %%T in (!__ES_J!) do for %%W in (%__ES_RX_SEGMENTS%) do if /i "%%T"=="%%W" exit /b 0
set "__ES_J=#!__ES_T:_=!#"
for %%W in (%__ES_RX_CONTAINS%) do if not "!__ES_J:%%W=!"=="!__ES_J!" exit /b 0
for %%W in (%__ES_RX_NSUFFIXES%) do if /i not "!__ES_J:%%W#=!"=="!__ES_J!" exit /b 0
exit /b 1

:es_camel
rem Puts "_" at the camelCase boundaries of __ES_KN ([a-z0-9][A-Z] and [A-Z][A-Z][a-z]), so
rem sessionKey becomes session_Key and HTTPProxy HTTP_Proxy. __ES_KU is the upper-case copy
rem made by :es_name_secret, __ES_KW the lower-case copy; a character is an upper-case letter
rem when it differs from its lower-case copy.
set "__ES_KW=!__ES_KN!"
for %%U in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do set "__ES_KW=!__ES_KW:%%U=%%U!"
if "!__ES_KW!"=="!__ES_KN!" exit /b 0
call :es_strlen __ES_KN __ES_KLEN
set /a "__ES_KE=__ES_KLEN-1"
set "__ES_KC="
for /l %%i in (0,1,!__ES_KE!) do if not "!__ES_KN:~%%i,1!"=="!__ES_KW:~%%i,1!" (set "__ES_KC=!__ES_KC!U") else if not "!__ES_KN:~%%i,1!"=="!__ES_KU:~%%i,1!" (set "__ES_KC=!__ES_KC!L") else set "__ES_KC=!__ES_KC!O"
set "__ES_KP=O!__ES_KC!"
set "__ES_KX=!__ES_KC:~1!O"
set "__ES_KO=!__ES_KN:~0,1!"
for /l %%i in (1,1,!__ES_KE!) do (
    if "!__ES_KC:~%%i,1!"=="U" if "!__ES_KP:~%%i,1!"=="U" (if "!__ES_KX:~%%i,1!"=="L" set "__ES_KO=!__ES_KO!_") else set "__ES_KO=!__ES_KO!_"
    set "__ES_KO=!__ES_KO!!__ES_KN:~%%i,1!"
)
set "__ES_KN=!__ES_KO!"
exit /b 0

:es_redact_value
rem Delayed expansion is on. VALUE and COMMAND LINE rules of spec/redaction.toml applied to
rem __ES_V. Where batch cannot find the exact end of a secret the whole value is replaced; URL
rem and bare user:password@host passwords are cut out exactly.
if not defined __ES_V exit /b 0
if not "!__ES_V:@@ES_REDACT_PKMARKER@@=!"=="!__ES_V!" (set "__ES_V=<redacted: private key>" & exit /b 0)
for %%W in (bearer basic) do if not "!__ES_V:%%W =!"=="!__ES_V!" call :es_redact_scheme %%W
for %%P in (%__ES_RX_PREFIXES%) do if not "!__ES_V:%%P=!"=="!__ES_V!" call :es_redact_token %%P
if not "!__ES_V:/t/=!"=="!__ES_V!" call :es_redact_conda
if "!__ES_V!"=="!__ES_PH!" exit /b 0
rem Cheap tests before the scan: a secret key needs a trigger word in the value without _ . -
rem (a key's joined name), an option a " -" or " /", a tool option also the tool's name.
set "__ES_KVNEED="
set "__ES_X=#!__ES_V!"
set "__ES_X=!__ES_X:_=!"
set "__ES_X=!__ES_X:.=!"
set "__ES_X=!__ES_X:-=!"
for %%W in (%__ES_RX_TRIGGERS%) do if not "!__ES_X:%%W=!"=="!__ES_X!" set "__ES_KVNEED=1"
set "__ES_OPTNEED="
set "__ES_TOOLNEED="
set "__ES_X= !__ES_V!"
set "__ES_X=!__ES_X:"= !"
set "__ES_X=!__ES_X:'= !"
if not "!__ES_X: -=!"=="!__ES_X!" set "__ES_OPTNEED=1"
if not "!__ES_X: /=!"=="!__ES_X!" set "__ES_OPTNEED=1"
if defined __ES_OPTNEED for %%T in (%__ES_RX_TOOLNAMES%) do if not "!__ES_X:%%T=!"=="!__ES_X!" set "__ES_TOOLNEED=1"
if defined __ES_KVNEED (call :es_redact_scan) else if defined __ES_OPTNEED call :es_redact_scan
if "!__ES_V!"=="!__ES_PH!" exit /b 0
if not "!__ES_V:://=!"=="!__ES_V!" call :es_redact_urls
if "!__ES_V:@=!"=="!__ES_V!" exit /b 0
if "!__ES_V::=!"=="!__ES_V!" exit /b 0
call :es_redact_bare
exit /b 0

:es_redact_scheme
rem %1 = bearer or basic: "<scheme> <8 or more characters without a space>" replaces the value.
set "__ES_S=!__ES_V!"
for /l %%I in (1,1,8) do if defined __ES_S (
    set "__ES_A=!__ES_S:*%1 =!"
    if "!__ES_A!"=="!__ES_S!" (set "__ES_S=") else (
        set "__ES_S=!__ES_A!"
        if defined __ES_A (
            set "__ES_X=!__ES_A:~0,8!"
            if not "!__ES_X:~7,1!"=="" if "!__ES_X: =!"=="!__ES_X!" (set "__ES_V=!__ES_PH!" & set "__ES_S=")
        )
    )
)
exit /b 0

:es_redact_conda
rem A conda channel token, "/t/<8 or more characters before the next />", replaces the value.
set "__ES_A=!__ES_V:*/t/=!"
if not defined __ES_A exit /b 0
set "__ES_X=!__ES_A:~0,8!"
if "!__ES_X:~7,1!"=="" exit /b 0
if not "!__ES_X:/=!"=="!__ES_X!" exit /b 0
if not "!__ES_X: =!"=="!__ES_X!" exit /b 0
set "__ES_V=!__ES_PH!"
exit /b 0

:es_redact_scan
rem Key/value, pair-key and option rules (__ES_KVNEED, __ES_OPTNEED set by :es_redact_value);
rem a hit replaces the whole value. One pass: "=" and ":" end key candidates, spaces end words.
call :es_strlen __ES_V __ES_LV
set /a "__ES_KS=0, __ES_WS=0, __ES_LVM=__ES_LV-1"
set "__ES_RHIT="
set "__ES_WSEP="
set "__ES_OPREV="
set "__ES_TOPTS="
for /l %%i in (0,1,!__ES_LVM!) do if not defined __ES_RHIT (
    set "__ES_C=!__ES_V:~%%i,1!"
    if "!__ES_C!"=="=" (
        if not defined __ES_WSEP set "__ES_WSEP=%%i"
        if defined __ES_KVNEED call :es_kv_at %%i e
    ) else if "!__ES_C!"==":" (
        if not defined __ES_WSEP set "__ES_WSEP=%%i"
        if defined __ES_KVNEED call :es_kv_at %%i c
    ) else if "!__ES_C!"==" " (
        if defined __ES_OPTNEED call :es_word_at %%i
        set "__ES_WSEP="
    )
)
if defined __ES_OPTNEED if not defined __ES_RHIT call :es_word_at !__ES_LV!
if defined __ES_RHIT set "__ES_V=!__ES_PH!"
exit /b 0

:es_kv_at
rem %1 = position of "=" (%2 e) or ":" (%2 c) in __ES_V. The key candidate is the text since the
rem previous separator without trailing spaces and one closing quote, after the last character
rem that cannot be part of a key: a superset of the key, so it over- rather than under-redacts.
set /a "__ES_KL=%1-__ES_KS"
set "__ES_KN="
if !__ES_KL! GTR 0 for /f "tokens=1,2" %%a in ("!__ES_KS! !__ES_KL!") do set "__ES_KN=!__ES_V:~%%a,%%b!"
set /a "__ES_KS=%1+1"
if not defined __ES_KN exit /b 0
for /l %%j in (1,1,16) do if defined __ES_KN if "!__ES_KN:~-1!"==" " set "__ES_KN=!__ES_KN:~0,-1!"
if not defined __ES_KN exit /b 0
set "__ES_Q=#!__ES_KN:~-1!"
set "__ES_Q=!__ES_Q:"=$!"
set "__ES_QX="
if "!__ES_Q!"=="#$" set "__ES_QX=1"
if "!__ES_Q!"=="#'" set "__ES_QX=1"
if defined __ES_QX set "__ES_KN=!__ES_KN:~0,-1!"
rem The quote after the key may be escaped (JSON inside a string): its backslash goes too.
if defined __ES_QX if defined __ES_KN if "!__ES_KN:~-1!"=="\" set "__ES_KN=!__ES_KN:~0,-1!"
if not defined __ES_KN exit /b 0
set "__ES_KN=!__ES_KN:"= !"
set "__ES_KN=!__ES_KN:;= !"
set "__ES_KN=!__ES_KN:,= !"
set "__ES_KN=!__ES_KN:&= !"
set "__ES_KN=!__ES_KN:|= !"
set "__ES_KN=!__ES_KN:<= !"
set "__ES_KN=!__ES_KN:>= !"
set "__ES_KN=!__ES_KN:(= !"
set "__ES_KN=!__ES_KN:)= !"
set "__ES_KN=!__ES_KN:?= !"
for %%c in (' / \ @ # $ + [ ] { } `) do set "__ES_KN=!__ES_KN:%%c= !"
if not "!__ES_KN: =!"=="!__ES_KN!" (
    set "__ES_KN=!__ES_KN!#"
    for /l %%j in (1,1,64) do (set "__ES_X=!__ES_KN:* =!" & if not "!__ES_X!"=="!__ES_KN!" set "__ES_KN=!__ES_X!")
    set "__ES_KN=!__ES_KN:~0,-1!"
)
if not defined __ES_KN exit /b 0
if "%2"=="e" for %%P in (%__ES_RX_PAIRS%) do if /i "!__ES_KN!"=="%%P" (set "__ES_RHIT=1" & exit /b 0)
call :es_name_secret && set "__ES_RHIT=1"
exit /b 0

:es_word_at
rem %1 = end of a word of __ES_V (a space or the end of the value): (-|--|/)<name with an
rem option word>, -u/--user/--proxy-user user:secret and -H/--header "<header word>: value".
rem __ES_WN is the word up to its first "=" or ":"; a path (a "/" or "\" in it) is no option.
set /a "__ES_WL=%1-__ES_WS, __ES_WNL=%1-__ES_WS"
set "__ES_WINL="
if defined __ES_WSEP (set /a "__ES_WNL=__ES_WSEP-__ES_WS" & set "__ES_WINL=1")
set "__ES_W="
set "__ES_WN="
if !__ES_WL! GTR 0 for /f "tokens=1-3" %%a in ("!__ES_WS! !__ES_WL! !__ES_WNL!") do (
    set "__ES_W=!__ES_V:~%%a,%%b!"
    if %%c GTR 0 set "__ES_WN=!__ES_V:~%%a,%%c!"
)
set /a "__ES_WS=%1+1"
if not defined __ES_W exit /b 0
if defined __ES_TOOLNEED call :es_tool_word
if defined __ES_RHIT exit /b 0
set "__ES_OP=!__ES_OPREV!"
set "__ES_OPREV="
if "!__ES_OP!"=="u" if not "!__ES_W::=!"=="!__ES_W!" (set "__ES_RHIT=1" & exit /b 0)
if "!__ES_OP!"=="h" for %%H in (%__ES_RX_HEADERS%) do if not "!__ES_W:%%H=!"=="!__ES_W!" (set "__ES_RHIT=1" & exit /b 0)
if not defined __ES_WN exit /b 0
set "__ES_Q=#!__ES_WN:~0,1!"
set "__ES_Q=!__ES_Q:"=$!"
if "!__ES_Q!"=="#$" set "__ES_WN=!__ES_WN:~1!"
if "!__ES_Q!"=="#'" set "__ES_WN=!__ES_WN:~1!"
if not defined __ES_WN exit /b 0
if "!__ES_WN!"=="-H" (set "__ES_OPREV=h" & exit /b 0)
if /i "!__ES_WN!"=="-u" (set "__ES_OPREV=u" & exit /b 0)
rem curl -ubob:secret, -Ubob:secret: the user option with its value attached.
set "__ES_X=!__ES_WN:~0,2!"
if /i "!__ES_X!"=="-u" if not "!__ES_W::=!"=="!__ES_W!" (set "__ES_RHIT=1" & exit /b 0)
set "__ES_X=!__ES_WN:~0,1!"
if not "!__ES_X!"=="-" if not "!__ES_X!"=="/" exit /b 0
set "__ES_X=!__ES_WN:~1!"
if not defined __ES_X exit /b 0
if not "!__ES_X:/=!"=="!__ES_X!" exit /b 0
if not "!__ES_X:\=!"=="!__ES_X!" exit /b 0
for %%O in (%__ES_RX_OPTIONS%) do if not "!__ES_X:%%O=!"=="!__ES_X!" (set "__ES_RHIT=1" & exit /b 0)
set "__ES_X=!__ES_X:"=!"
if /i "!__ES_X!"=="-user" goto :es_word_user
if /i "!__ES_X!"=="-proxy-user" goto :es_word_user
if /i "!__ES_X!"=="-header" goto :es_word_header
exit /b 0
:es_word_user
if not defined __ES_WINL (set "__ES_OPREV=u" & exit /b 0)
if not "!__ES_W::=!"=="!__ES_W!" set "__ES_RHIT=1"
exit /b 0
:es_word_header
if not defined __ES_WINL (set "__ES_OPREV=h" & exit /b 0)
for %%H in (%__ES_RX_HEADERS%) do if not "!__ES_W:%%H=!"=="!__ES_W!" set "__ES_RHIT=1"
exit /b 0

:es_tool_word
rem TOOL OPTIONS: a word __ES_W that starts with an option of a tool named earlier in the value is
rem a hit ("-" options case-sensitive, "/" options not, an opening quote skipped); a word whose
rem last part (after quotes, / \ & | ( ) < > and FOR's , ; =) names a tool, with or without .exe
rem .cmd .bat .com, adds that tool's options to __ES_TOPTS.
if not defined __ES_TOPTS goto :es_tool_name
set "__ES_X=!__ES_W!"
set "__ES_Q=#!__ES_X:~0,1!"
set "__ES_Q=!__ES_Q:"=$!"
if "!__ES_Q!"=="#$" set "__ES_X=!__ES_X:~1!"
if "!__ES_Q!"=="#'" set "__ES_X=!__ES_X:~1!"
if not defined __ES_X exit /b 0
for %%o in (!__ES_TOPTS!) do (
    set "__ES_Y=%%o"
    if "!__ES_Y:~0,1!"=="/" (
        for %%n in (2 3 4) do if /i "!__ES_X:~0,%%n!"=="%%o" set "__ES_RHIT=1"
    ) else (
        for %%n in (2 3 4) do if "!__ES_X:~0,%%n!"=="%%o" set "__ES_RHIT=1"
    )
)
if defined __ES_RHIT exit /b 0
:es_tool_name
rem No FOR list for words with * (a file name wildcard); ? becomes a separator.
set "__ES_X= !__ES_W!"
if not "!__ES_X!"=="!__ES_X:**=!" exit /b 0
set "__ES_X=!__ES_X:?= !"
set "__ES_X=!__ES_X:"= !"
set "__ES_X=!__ES_X:'= !"
set "__ES_X=!__ES_X:/= !"
set "__ES_X=!__ES_X:\= !"
set "__ES_X=!__ES_X:&= !"
set "__ES_X=!__ES_X:|= !"
set "__ES_X=!__ES_X:(= !"
set "__ES_X=!__ES_X:)= !"
set "__ES_X=!__ES_X:<= !"
set "__ES_X=!__ES_X:>= !"
set "__ES_TN="
for %%t in (!__ES_X!) do set "__ES_TN=%%t"
if not defined __ES_TN exit /b 0
set "__ES_TN=!__ES_TN!#"
for %%e in (.exe .cmd .bat .com) do set "__ES_TN=!__ES_TN:%%e#=#!"
for %%P in (%__ES_RX_TOOLOPTS%) do for /f "tokens=1,2 delims=:" %%a in ("%%P") do if /i "!__ES_TN!"=="%%a#" set "__ES_TOPTS=!__ES_TOPTS! %%b"
exit /b 0

:es_redact_urls
rem scheme://user:password@host keeps the user and the host; only the password is replaced.
set "__ES_UPOS=0"
for /l %%I in (1,1,12) do if defined __ES_UPOS call :es_redact_url_at
exit /b 0
:es_redact_url_at
rem In a batch file !UNDEFINED:x=y! expands to the text "x=y", so every variable is tested
rem with "if defined" (or carries a # sentinel) before a substitution is applied to it.
for %%P in (!__ES_UPOS!) do set "__ES_S=!__ES_V:~%%P!"
if not defined __ES_S (set "__ES_UPOS=" & exit /b 0)
set "__ES_A=!__ES_S:*://=!"
if "!__ES_A!"=="!__ES_S!" (set "__ES_UPOS=" & exit /b 0)
if not defined __ES_A (set "__ES_UPOS=" & exit /b 0)
call :es_strlen __ES_S __ES_LS
call :es_strlen __ES_A __ES_LA
set /a "__ES_HS=__ES_UPOS+__ES_LS-__ES_LA, __ES_UPOS=__ES_HS"
set "__ES_AUTH=!__ES_A!"
call :es_cut_auth "/"
call :es_cut_auth "?"
call :es_cut_auth "#"
call :es_cut_auth " "
set "__ES_UTOK=1"
goto :es_redact_userinfo

:es_redact_bare
rem Bare userinfo, user:password@host without a scheme anywhere in the text (a proxy written
rem without http://, curl -x user:pw@proxy): only the password is replaced. A token is a run
rem without whitespace and quotes; the user runs from its start to the first ":" (no /; "@" for
rem UPN logins such as john.doe@corp.com and \ for DOMAIN\user are part of it), the password
rem (no / or \) to an "@" that :es_bare_at accepts, else on to the next "@". One
rem pass over __ES_W (the value with each quote as ' and a tab as a space, same positions)
rem records the passwords in __ES_UM, the last one first; they are then replaced from the end,
rem so the positions of the earlier ones stay valid.
rem A token that is done (a match, or a / or \ that rules one out) starts again after the next
rem ; or , so every entry of a list such as a:pw@h1;b:pw2@h2 is checked.
set "__ES_W=!__ES_V:"='!"
set "__ES_W=!__ES_W:	= !"
call :es_strlen __ES_W __ES_LW
set /a "__ES_LWM=__ES_LW-1, __ES_TS=0, __ES_UC=-1, __ES_UB=0"
set "__ES_UM="
for /l %%i in (0,1,!__ES_LWM!) do (
    set "__ES_C=!__ES_W:~%%i,1!"
    if "!__ES_C!"==" " (set /a "__ES_TS=%%i+1, __ES_UC=-1, __ES_UB=0") else if "!__ES_C!"=="'" (set /a "__ES_TS=%%i+1, __ES_UC=-1, __ES_UB=0") else if !__ES_UB! EQU 0 (
        if "!__ES_C!"=="/" (set "__ES_UB=1") else if "!__ES_C!"==":" (
            if !__ES_UC! LSS 0 if %%i GTR !__ES_TS! (set "__ES_UC=%%i") else (set "__ES_UB=1")
        ) else if "!__ES_C!"=="\" (
            if !__ES_UC! GEQ 0 set "__ES_UB=1"
        ) else if "!__ES_C!"=="@" (
            if !__ES_UC! GEQ 0 call :es_bare_at %%i
        )
    ) else if "!__ES_C!"==";" (set /a "__ES_TS=%%i+1, __ES_UC=-1, __ES_UB=0") else if "!__ES_C!"=="," (set /a "__ES_TS=%%i+1, __ES_UC=-1, __ES_UB=0")
)
for %%m in (!__ES_UM!) do for /f "tokens=1,2 delims=:" %%a in ("%%m") do (
    set /a "__ES_X=%%a+%%b"
    for %%e in (!__ES_X!) do set "__ES_V=!__ES_V:~0,%%a!!__ES_PH!!__ES_V:~%%e!"
)
exit /b 0
:es_bare_at
rem %1 = position of an "@" in __ES_W. When a host follows ([A-Za-z0-9._-]+ or [IPv6]), then an
rem optional :port of 1-5 digits and the end, whitespace, a quote or / , ; ) ] } > < | & # ? \,
rem the password before it is recorded and the rest of the token is done (__ES_UB=1). The text
rem is cut at the first of those characters (after the "]" of an IPv6 address); the ~ in front
rem keeps the cut from skipping a leading one.
set /a "__ES_PWL=%1-__ES_UC-1, __ES_HP=%1+1"
if !__ES_PWL! LSS 1 exit /b 0
set "__ES_H="
for %%a in (!__ES_HP!) do set "__ES_H=!__ES_W:~%%a,300!"
if not defined __ES_H exit /b 0
set "__ES_HO="
if "!__ES_H:~0,1!"=="[" goto :es_bare_at_v6
for /f "tokens=1 delims=',;)]}><|&/#?\ " %%h in ("~!__ES_H!") do set "__ES_H=%%h"
set "__ES_H=!__ES_H:~1!"
if not defined __ES_H exit /b 0
set "__ES_HN=!__ES_H!"
set "__ES_R=!__ES_H:*:=!"
if "!__ES_R!"=="!__ES_H!" goto :es_bare_at_name
if not defined __ES_R exit /b 0
call :es_strlen __ES_H __ES_LH
call :es_strlen __ES_R __ES_LR
set /a "__ES_LN=__ES_LH-__ES_LR-1"
if !__ES_LN! LSS 1 exit /b 0
for %%n in (!__ES_LN!) do set "__ES_HN=!__ES_H:~0,%%n!"
set "__ES_HO=!__ES_R!"
:es_bare_at_name
for /f "eol=. delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" %%x in ("a!__ES_HN!") do exit /b 0
goto :es_bare_at_port
:es_bare_at_v6
set "__ES_R=!__ES_H:*]=!"
if "!__ES_R!"=="!__ES_H!" exit /b 0
call :es_strlen __ES_H __ES_LH
set "__ES_LR=0"
if defined __ES_R call :es_strlen __ES_R __ES_LR
set /a "__ES_LN=__ES_LH-__ES_LR-2"
if !__ES_LN! LSS 1 exit /b 0
for %%n in (!__ES_LN!) do set "__ES_HN=!__ES_H:~1,%%n!"
for /f "eol=. delims=0123456789abcdefABCDEF:." %%x in ("0!__ES_HN!") do exit /b 0
if not defined __ES_R goto :es_bare_at_hit
for /f "tokens=1 delims=',;)]}><|&/#?\ " %%h in ("~!__ES_R!") do set "__ES_R=%%h"
set "__ES_R=!__ES_R:~1!"
if not defined __ES_R goto :es_bare_at_hit
if not "!__ES_R:~0,1!"==":" exit /b 0
set "__ES_HO=!__ES_R:~1!"
if not defined __ES_HO exit /b 0
:es_bare_at_port
if not defined __ES_HO goto :es_bare_at_hit
if not "!__ES_HO:~5!"=="" exit /b 0
for /f "delims=0123456789" %%z in ("0!__ES_HO!") do exit /b 0
:es_bare_at_hit
set /a "__ES_X=__ES_UC+1, __ES_UB=1"
set "__ES_UM=!__ES_X!:!__ES_PWL! !__ES_UM!"
exit /b 0

:es_redact_userinfo
rem __ES_AUTH is the authority starting at __ES_HS in __ES_V. The password runs from the first
rem ":" of the userinfo to the LAST "@"; a userinfo without ":" of token length is replaced
rem whole when __ES_UTOK is set (a token used as the user name of a URL).
if not defined __ES_AUTH exit /b 0
rem __ES_H: the host after the last @, plus the sentinel (so an empty host stays defined).
set "__ES_H=!__ES_AUTH!#"
for /l %%J in (1,1,8) do (set "__ES_X=!__ES_H:*@=!" & if not "!__ES_X!"=="!__ES_H!" set "__ES_H=!__ES_X!")
if "!__ES_H!"=="!__ES_AUTH!#" exit /b 0
call :es_strlen __ES_AUTH __ES_LAU
call :es_strlen __ES_H __ES_LH
set /a "__ES_UIL=__ES_LAU-__ES_LH"
if !__ES_UIL! LSS 1 exit /b 0
for %%a in (!__ES_UIL!) do set "__ES_UI=!__ES_AUTH:~0,%%a!"
set "__ES_PW=!__ES_UI:*:=!"
if "!__ES_PW!"=="!__ES_UI!" if defined __ES_UTOK if !__ES_UIL! GEQ !__ES_RX_MINLEN! set "__ES_PW=!__ES_UI!#"
if "!__ES_PW!"=="!__ES_UI!" exit /b 0
if "!__ES_PW!"=="!__ES_UI!#" set "__ES_PW=!__ES_UI!"
if not defined __ES_PW exit /b 0
call :es_strlen __ES_PW __ES_LPW
call :es_strlen __ES_PH __ES_LPH
set /a "__ES_C1=__ES_HS+__ES_UIL-__ES_LPW, __ES_C2=__ES_HS+__ES_UIL"
for /f "tokens=1,2" %%a in ("!__ES_C1! !__ES_C2!") do set "__ES_V=!__ES_V:~0,%%a!!__ES_PH!!__ES_V:~%%b!"
set /a "__ES_UPOS=__ES_C1+__ES_LPH+1"
exit /b 0
:es_cut_auth
if not defined __ES_AUTH exit /b 0
set "__ES_X=!__ES_AUTH:*%~1=!"
if "!__ES_X!"=="!__ES_AUTH!" exit /b 0
call :es_strlen __ES_X __ES_LX
call :es_strlen __ES_AUTH __ES_LAU
set /a "__ES_LAU-=__ES_LX+1"
for %%a in (!__ES_LAU!) do set "__ES_AUTH=!__ES_AUTH:~0,%%a!"
exit /b 0

:es_redact_token
rem A token prefix (case-sensitive) at a word start followed by token characters up to the
rem minimum length makes the whole value secret.
set "__ES_TP=%~1"
call :es_strlen __ES_TP __ES_LTP
set /a "__ES_TW=__ES_RX_MINLEN, __ES_X=__ES_LTP+4"
if !__ES_X! GTR !__ES_TW! set "__ES_TW=!__ES_X!"
set "__ES_TPOS=0"
for /l %%I in (1,1,12) do if defined __ES_TPOS call :es_redact_token_at
exit /b 0
:es_redact_token_at
for %%P in (!__ES_TPOS!) do set "__ES_S=!__ES_V:~%%P!"
if not defined __ES_S (set "__ES_TPOS=" & exit /b 0)
set "__ES_A=!__ES_S:*%__ES_TP%=!"
if "!__ES_A!"=="!__ES_S!" (set "__ES_TPOS=" & exit /b 0)
call :es_strlen __ES_S __ES_LS
call :es_strlen __ES_A __ES_LA
set /a "__ES_OCC=__ES_TPOS+__ES_LS-__ES_LA-__ES_LTP, __ES_TPOS=__ES_OCC+1"
for /f "tokens=1,2" %%a in ("!__ES_OCC! !__ES_LTP!") do set "__ES_X=!__ES_V:~%%a,%%b!"
if not "!__ES_X!"=="!__ES_TP!" exit /b 0
if !__ES_OCC! GTR 0 (
    set /a "__ES_Y=__ES_OCC-1"
    for %%a in (!__ES_Y!) do set "__ES_C=!__ES_V:~%%a,1!"
    call :es_is_wordchar && exit /b 0
)
for /f "tokens=1,2" %%a in ("!__ES_OCC! !__ES_TW!") do set "__ES_X=!__ES_V:~%%a,%%b!"
set /a "__ES_Y=__ES_TW-1"
for %%a in (!__ES_Y!) do if "!__ES_X:~%%a,1!"=="" exit /b 0
call :es_all_tokenchars || exit /b 0
set "__ES_V=!__ES_PH!"
set "__ES_TPOS="
exit /b 0
:es_is_wordchar
rem Success when __ES_C is a word character [A-Za-z0-9_-]. The leading # keeps __ES_Y defined
rem while characters are removed (see :es_redact_url_at); a quote becomes $.
if not defined __ES_C exit /b 1
set "__ES_Y=#!__ES_C:"=$!"
for %%c in (a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 _ -) do set "__ES_Y=!__ES_Y:%%c=!"
if "!__ES_Y!"=="#" exit /b 0
exit /b 1
:es_all_tokenchars
rem Success when every character of __ES_X is a token character [A-Za-z0-9_-.+/=]. "=" cannot
rem be removed by substitution, so trailing ones are cut after the other characters are gone.
set "__ES_Y=#!__ES_X:"=$!"
for %%c in (a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 _ - . + /) do set "__ES_Y=!__ES_Y:%%c=!"
for /l %%i in (1,1,%__ES_TW%) do if "!__ES_Y:~-1!"=="=" set "__ES_Y=!__ES_Y:~0,-1!"
if "!__ES_Y!"=="#" exit /b 0
exit /b 1

:es_strlen
rem Length of the variable named by the first argument, stored in the variable named by the second.
setlocal EnableDelayedExpansion
set "__ES_SL=!%~1!#"
set "__ES_SN=0"
for %%P in (16384 8192 4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do if not "!__ES_SL:~%%P,1!"=="" (set /a "__ES_SN+=%%P" & set "__ES_SL=!__ES_SL:~%%P!")
endlocal & set "%~2=%__ES_SN%"
exit /b 0

:es_local_drives
rem Drive letters of local volumes (mountvol) and subst drives; anything else is never touched.
set "__ES_LOCALDRV=;"
if not defined __ES_CAP goto :es_local_drives_child
"%__ES_SYS%\mountvol.exe" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1" %%L in ("%__ES_CAP%") do call :es_local_drive_add "%%L"
"%__ES_SYS%\subst.exe" <nul >"%__ES_CAP%" 2>nul
for /f "usebackq tokens=1" %%L in ("%__ES_CAP%") do call :es_local_drive_add "%%L"
goto :es_local_drives_end
:es_local_drives_child
for /f "tokens=1" %%L in ('%__ES_SYS%\mountvol.exe 2^>nul') do call :es_local_drive_add "%%L"
for /f "tokens=1" %%L in ('%__ES_SYS%\subst.exe 2^>nul') do call :es_local_drive_add "%%L"
:es_local_drives_end
if "%__ES_LOCALDRV%"==";" set "__ES_LOCALDRV=;%__ES_SYSDRIVE:~0,1%;"
exit /b 0
:es_local_drive_add
set "__ES_X=%~1"
if not "%__ES_X:~1,2%"==":\" exit /b 0
if "%__ES_X:~3%"=="" (set "__ES_LOCALDRV=%__ES_LOCALDRV%%__ES_X:~0,1%;" & exit /b 0)
if "%__ES_X:~3%"==":" set "__ES_LOCALDRV=%__ES_LOCALDRV%%__ES_X:~0,1%;"
exit /b 0

:es_seen_once
rem Exit code 0 the first time the value of the named variable is seen, 1 afterwards.
setlocal EnableDelayedExpansion
set "__ES_X=__ES_SEEN_!%~1!"
for /f "delims=" %%K in ("!__ES_X!") do if defined %%K exit /b 1
endlocal & set "%__ES_X%=1"
exit /b 0
