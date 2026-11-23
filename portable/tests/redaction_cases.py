"""Redaction case tables shared by the implementations (data only, no test code).

tests/test_ps_redaction.py runs ALL_CASES (shared + ps-only) through envscan.ps1,
tests/test_sh_redaction.py runs SHARED_CASES + SH_CASES through envscan.sh, and
tests/test_cross_redaction.py runs each side's cases through the other implementation.
tests/shared_cases.py exports every table as JSON for the JScript and Go harnesses.
Tables: SHARED_CASES (names, values, lines, text, command lines, named values), PS_CASES
(written for ps1) and SH_CASES (written for sh); KNOWN_DIVERGENCES lists what fails today.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

HEX40 = "0123456789abcdef0123456789abcdef01234567"
PH = "<redacted>"


@dataclass(frozen=True)
class Case:
    name: str
    fn: str
    args: tuple[str, ...]
    expected: Any = None
    gone: tuple[str, ...] = ()
    kept: tuple[str, ...] = ()
    exact: bool = True


def _exact(name: str, fn: str, value: str, expected: Any) -> Case:
    return Case(name, fn, (value,), expected=expected)


def _gone(name: str, fn: str, value: str, gone: tuple[str, ...], kept: tuple[str, ...] = ()) -> Case:
    return Case(name, fn, (value,), gone=gone, kept=kept, exact=False)


SECRET_NAMES = {
    "sessionKey": True, "signingKey": True, "licenseKey": True, "keystorePwd": True, "npmAuthIdent": True,
    "npmAuthToken": True, "PW": True, "DB_PSWD": True, "PASSCODE": True, "JWT": True, "SENTRY_DSN": True,
    "CONN_STR": True, "MyConnString": True, "SIG": True, "http.extraheader": True,
    "http.https://dev.azure.com/.extraheader": True, "SLACK_WEBHOOK_URL": True, "APIKEY": True,
    "SESSIONKEY": True, "X-Api-Key": True, "-Dhttp.proxyPassword": True, "systemProp.https.proxyPassword": True,
    "HTTPProxyPassword": True, "GITHUB_TOKEN": True, "credential.helper": True,
    "KEY": False, "PWD": False, "OLDPWD": False, "PSModulePath": False, "KEYBOARD_LAYOUT": False,
    "KeyboardLayout": False, "DB_PASSWORD_FILE": False, "passwordFile": False, "http.proxyAuthMethod": False,
    "PROXY_AUTH_METHOD": False, "TOKEN_TYPE": False, "SSH_AUTH_SOCK": False, "PATH": False, "JAVA_HOME": False,
    "ProgramFiles": False, "ChocolateyInstall": False, "value": False, "name": False, "registry": False,
    "GIT_ASKPASS": False, "TOKENIZERS_PARALLELISM": False, "NUMBER_OF_PROCESSORS": False, "ProxyOverride": False,
    "SSHPASS": True, "DBPASS": True, "MYSQLPASS": True, "SSH_ASKPASS": False,
    "HTTP_AUTHORIZATION": True, "proxy_authorization": True,
}

# Case names carry an index: PowerShell hashtable keys are case-insensitive (sessionKey vs SESSIONKEY).
NAME_CASES = tuple(Case(f"name{i:02d}:{n}", "Test-EsSecretName", (n,), expected=s)
                   for i, (n, s) in enumerate(SECRET_NAMES.items()))

VALUE_CASES = (
    _exact("url_at_in_password", "Protect-EsValue", "https://user:p@ss@repo.corp/x", f"https://user:{PH}@repo.corp/x"),
    _exact("url_at_in_user", "Protect-EsValue", "https://p@ss:word@host/", f"https://p@ss:{PH}@host/"),
    _exact("url_token_user", "Protect-EsValue", f"https://{HEX40}@github.com/org/repo", f"https://{PH}@github.com/org/repo"),
    _exact("url_ssh_port", "Protect-EsValue", "ssh://git@github.com:22/org/repo", "ssh://git@github.com:22/org/repo"),
    _exact("url_short_user", "Protect-EsValue", "https://git@dev.azure.com/org", "https://git@dev.azure.com/org"),
    _exact("url_host_port", "Protect-EsValue", "http://proxy.corp:8080", "http://proxy.corp:8080"),
    _exact("url_sas", "Protect-EsValue", "https://h.example/x?sv=2020&sig=AbC123%2Fxyz&se=1",
           f"https://h.example/x?sv=2020&sig={PH}&se=1"),
    _exact("url_access_token", "Protect-EsValue", "https://h.example/x?access_token=abc123def&page=2",
           f"https://h.example/x?access_token={PH}&page=2"),
    _exact("url_conda_token", "Protect-EsValue", "https://conda.example/t/tk-0123456789abcdef/main",
           f"https://conda.example/t/{PH}/main"),
    # Unquoted values continue past , ; & # unless another key follows.
    _exact("run_comma", "Protect-EsValue", "-e DB_PASS=Hun,ter2 -e X=1", f"-e DB_PASS={PH} -e X=1"),
    _exact("run_semicolon", "Protect-EsValue", "MYSQL_PWD=abc;def", f"MYSQL_PWD={PH}"),
    _exact("run_double_separator", "Protect-EsValue", "MYSQL_PWD=abc;;def", f"MYSQL_PWD={PH}"),
    _exact("run_trailing_separator", "Protect-EsValue", "token=abc; next", f"token={PH}; next"),
    _exact("run_equals_inside", "Protect-EsValue", "Pwd=a=b;Database=y", f"Pwd={PH};Database=y"),
    _exact("run_colon_inside", "Protect-EsValue", "password=ab:cd next", f"password={PH} next"),
    _exact("run_close_paren_inside", "Protect-EsValue", "password=ab)cd next", f"password={PH} next"),
    _exact("run_pipe_inside", "Protect-EsValue", "password=a|b next", f"password={PH} next"),
    _exact("run_quote_inside", "Protect-EsValue", 'password=a"b next', f"password={PH} next"),
    _exact("run_wrapped_in_parens", "Protect-EsValue", "(token=abc) && x", f"(token={PH}) && x"),
    _exact("run_compact_json", "Protect-EsValue", '{"password":abc,"user":"x"}', f'{{"password":{PH},"user":"x"}}'),
    _exact("run_leading_separator", "Protect-EsValue", "Pwd=;abc", f"Pwd={PH}"),
    # Redaction runs more than once over the same text (safety net): it must be idempotent.
    _exact("idempotent_secret_key", "Protect-EsValue", f"password={PH};Database=x", f"password={PH};Database=x"),
    _exact("idempotent_pair_key", "Protect-EsValue", f"Server=db;Pwd={PH}", f"Server=db;Pwd={PH}"),
    _exact("run_hash", "Protect-EsValue", "token=abc#def", f"token={PH}"),
    _exact("run_pair_key", "Protect-EsValue", "Server=db;Pwd=ab;cd", f"Server=db;Pwd={PH}"),
    _exact("run_next_key", "Protect-EsValue", "Server=db;Pwd=abc;Database=x", f"Server=db;Pwd={PH};Database=x"),
    _exact("run_next_key_comma", "Protect-EsValue", "password=abc,user=bob", f"password={PH},user=bob"),
    _exact("proxy_without_scheme", "Protect-EsValue", "user:hunter2@proxy.corp:8080", f"user:{PH}@proxy.corp:8080"),
    _exact("path_with_at", "Protect-EsValue", "C:\\Users\\me\\node_modules\\@types", "C:\\Users\\me\\node_modules\\@types"),
    _exact("git_scp_url", "Protect-EsValue", "git@github.com:org/repo.git", "git@github.com:org/repo.git"),
    _exact("java_options", "Protect-EsValue", "-Dhttp.proxyHost=p -Dhttp.proxyPassword=hunter2 -Dx=1",
           f"-Dhttp.proxyHost=p -Dhttp.proxyPassword={PH} -Dx=1"),
    _exact("conn_password", "Protect-EsValue", "Server=db;User Id=u;Password=abc;Database=x",
           f"Server=db;User Id=u;Password={PH};Database=x"),
    _exact("conn_pwd", "Protect-EsValue", "Server=db;Uid=u;Pwd=abc;", f"Server=db;Uid=u;Pwd={PH};"),
    _exact("json_inline", "Protect-EsValue", '{"user":"a","password":"b"}', f'{{"user":"a","password":"{PH}"}}'),
    _gone("json_nested_inline", "Protect-EsValue", f'{{"github-oauth":{{"github.com":"{HEX40}"}}}}', (HEX40,), ('"github-oauth"',)),
    _exact("flow_mapping", "Protect-EsValue", "{user: a, password: b}", f"{{user: a, password: {PH}}}"),
    _exact("bearer", "Protect-EsValue", "Authorization: Bearer abcdefghijklmnop", f"Authorization: Bearer {PH}"),
    _exact("authorization_json", "Protect-EsValue", '"authorization": "xyz123"', f'"authorization": "{PH}"'),
    _exact("nuget_source", "Protect-EsValue", '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />',
           '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'),
    _exact("plain_path", "Protect-EsValue", "C:\\Program Files\\nodejs\\node.exe", "C:\\Program Files\\nodejs\\node.exe"),
    _exact("time_and_drive", "Protect-EsValue", "started 12:30 on C:\\work", "started 12:30 on C:\\work"),
    _exact("pgp_block", "Protect-EsValue", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "<redacted: private key>"),
    # Review 2026-11-11, finding 5: user:password@host without a scheme inside a longer value.
    _exact("userinfo_in_words", "Protect-EsValue", "--proxy bob:Hunter2pw@proxy.corp:3128 --x",
           f"--proxy bob:{PH}@proxy.corp:3128 --x"),
    _exact("userinfo_domain_user", "Protect-EsValue", "CORP\\jdoe:Secr3t@proxy.corp:8080", f"CORP\\jdoe:{PH}@proxy.corp:8080"),
    _exact("userinfo_windows_path_kept", "Protect-EsValue", "C:\\tools\\bin@2\\x.exe", "C:\\tools\\bin@2\\x.exe"),
    # An '@' inside the password: the password runs to the '@' before a valid host (like the URL rule).
    _exact("userinfo_at_in_password", "Protect-EsValue", "--proxy user:p@ss@proxy.corp:8080 --x",
           f"--proxy user:{PH}@proxy.corp:8080 --x"),
    _exact("userinfo_host_then_path", "Protect-EsValue", "bob:pw4Secret@proxy:3128/x y", f"bob:{PH}@proxy:3128/x y"),
    # Second review 2026-11-11: a user name with "@" (UPN), and # ? \ after the host.
    _exact("userinfo_upn_user", "Protect-EsValue", "john.doe@corp.com:S3cretPw@proxy.corp:8080",
           f"john.doe@corp.com:{PH}@proxy.corp:8080"),
    _exact("userinfo_then_fragment", "Protect-EsValue", "jdoe:S3cretPw@proxy.corp#frag", f"jdoe:{PH}@proxy.corp#frag"),
    _exact("userinfo_then_query", "Protect-EsValue", "jdoe:S3cretPw@proxy.corp?x=1", f"jdoe:{PH}@proxy.corp?x=1"),
    _exact("userinfo_then_backslash", "Protect-EsValue", "jdoe:S3cretPw@proxy.corp\\share",
           f"jdoe:{PH}@proxy.corp\\share"),
    _exact("upn_with_port_kept", "Protect-EsValue", "see john.doe@corp.com:8080 now", "see john.doe@corp.com:8080 now"),
    # Second review 2026-11-11: JSON or a quoted value inside a string, with escaped quotes.
    _exact("escaped_json_inline", "Protect-EsValue", '{\\"password\\":\\"hunter2\\"}', f'{{\\"password\\":\\"{PH}\\"}}'),
    _exact("escaped_quoted_value", "Protect-EsValue", 'password=\\"hunter two\\" next', f'password=\\"{PH}\\" next'),
    _gone("escaped_json_authorization", "Protect-EsValue", '{\\"Authorization\\":\\"Token abcdefghij\\"}',
          ("abcdefghij",), ('{\\"Authorization\\":',)),
    # Third review 2026-11-12: a port followed by sentence punctuation.
    _exact("userinfo_port_then_dot", "Protect-EsValue", "use user:Hunter2pw@host:80.", f"use user:{PH}@host:80."),
    _exact("userinfo_port_then_bang", "Protect-EsValue", "use user:Hunter2pw@host:80!", f"use user:{PH}@host:80!"),
    # Security review 2026-11-12: several user:pw@host entries joined by ; or , (WinINET ProxyServer).
    _gone("userinfo_list_semicolon", "Protect-EsValue", "http=svc:Secr3tA@proxy.corp:80;https=svc:Secr3tB@proxy.corp:80",
          ("Secr3tA", "Secr3tB"), ("proxy.corp:80",)),
    _gone("userinfo_list_comma", "Protect-EsValue", "u:Secr3tA@h1:80,u:Secr3tB@h2:80", ("Secr3tA", "Secr3tB"), ("h2:80",)),
)

LINE_CASES = (
    _exact("yaml_list_env", "Protect-EsLine", "- DB_PASSWORD=x", f"- DB_PASSWORD={PH}"),
    _exact("yaml_list_map", "Protect-EsLine", "  - password: x", f"  - password: {PH}"),
    _exact("yarn_ident", "Protect-EsLine", 'npmAuthIdent: "user:pass"', f"npmAuthIdent: {PH}"),
    _exact("nuget_password", "Protect-EsLine", '<add key="Password" value="AQAAAN" />', f'<add key="Password" value="{PH}" />'),
    _exact("nuget_apikey", "Protect-EsLine", '<add key="https://www.nuget.org/api/v2" value="AQAAANCMnd8B" />',
           f'<add key="https://www.nuget.org/api/v2" value="{PH}" />'),
    _exact("name_value_attr", "Protect-EsLine", '<parameter name="dbPassword" value="x" />',
           f'<parameter name="dbPassword" value="{PH}" />'),
    _exact("connection_string_attr", "Protect-EsLine", '<add name="Main" connectionString="Server=a;Password=abc;" />',
           f'<add name="Main" connectionString="{PH}" />'),
    _exact("git_extraheader", "Protect-EsLine", "http.extraheader=AUTHORIZATION: basic eHl6", f"http.extraheader={PH}"),
    _exact("private_token_header", "Protect-EsLine", "PRIVATE-TOKEN: glpat-abc", f"PRIVATE-TOKEN: {PH}"),
    _exact("gemrc_key", "Protect-EsLine", ":rubygems_api_key: rubygems_0123456789abcdef", f":rubygems_api_key: {PH}"),
    _exact("export_token", "Protect-EsLine", "export GITHUB_TOKEN=abc", f"export GITHUB_TOKEN={PH}"),
    _exact("npm_registry", "Protect-EsLine", "registry=https://npm.corp.example/repository/npm/",
           "registry=https://npm.corp.example/repository/npm/"),
    _exact("email", "Protect-EsLine", "email=dev@corp.example", "email=dev@corp.example"),
    _exact("inline_table", "Protect-EsLine", 'myorg = { token = "x", url = "https://r.example" }',
           f'myorg = {{ token = "{PH}", url = "https://r.example" }}'),
    _exact("xml_element", "Protect-EsLine", "<password>s3cret</password>", f"<password>{PH}</password>"),
    # Review 2026-11-11, finding 5: user:password@host in config lines (cargo, pip).
    _exact("userinfo_quoted", "Protect-EsLine", 'proxy = "bob:Hunter2pw@proxy.corp:3128"',
           f'proxy = "bob:{PH}@proxy.corp:3128"'),
    _exact("userinfo_bare", "Protect-EsLine", "proxy = bob:Hunter2pw@proxy.corp:3128", f"proxy = bob:{PH}@proxy.corp:3128"),
    _exact("git_scp_url_kept", "Protect-EsLine", "url = git@github.com:org/repo.git", "url = git@github.com:org/repo.git"),
    # Finding 12: escaped quotes, values that only start with the placeholder, *AUTHORIZATION keys.
    _gone("json_escaped_quote", "Protect-EsLine", '{"password":"abc\\"Sup3rS3cret"}', ("Sup3rS3cret",), ('{"password":',)),
    _gone("placeholder_prefix", "Protect-EsLine", f"password={PH}Rest0fSecret", ("Rest0fSecret",), ("password=",)),
    _gone("token_then_rest", "Protect-EsLine", f"password=ghp_{'A' * 36}!Rest0fSecret", ("Rest0fSecret", "ghp_"),
          ("password=",)),
    _gone("colon_token", "Protect-EsLine", f"password=xyz:ghp_{'B' * 36}", ("xyz", "ghp_", f"{PH}>"), ("password=",)),
    _gone("json_proxy_authorization", "Protect-EsLine", '"proxy_authorization": "Zm9vYmFyYmF6"', ("Zm9vYmFyYmF6",),
          ('"proxy_authorization":',)),
    # Second review 2026-11-11.
    _exact("userinfo_upn_line", "Protect-EsLine", "proxy = john.doe@corp.com:S3cretPw@proxy.corp:8080",
           f"proxy = john.doe@corp.com:{PH}@proxy.corp:8080"),
    _gone("escaped_json_line", "Protect-EsLine", 'CFG={\\"user\\":\\"bob\\",\\"password\\":\\"hunter2\\"}', ("hunter2",),
          ('\\"user\\":\\"bob\\"',)),
    # Third review 2026-11-12: user:password@host:port as a whole line is not a key/value pair.
    _exact("userinfo_whole_line", "Protect-EsLine", "svc:pw@proxy.corp:8080", f"svc:{PH}@proxy.corp:8080"),
    _exact("userinfo_yaml_item", "Protect-EsLine", "- svc:pw@proxy.corp:8080", f"- svc:{PH}@proxy.corp:8080"),
    # Security review 2026-11-12: key and value separated by whitespace only (Groovy, yarn classic).
    _gone("space_key_double_quote", "Protect-EsLine", '    password "CanaryGradlePw"', ("CanaryGradlePw",), ("password",)),
    _gone("space_key_single_quote", "Protect-EsLine", "  token 'CanaryTok123'", ("CanaryTok123",), ("token",)),
    _gone("space_key_groovy_block", "Protect-EsLine", 'credentials { username "svc"  password "CanaryGradlePw" }',
          ("CanaryGradlePw",), ('username "svc"',)),
    _gone("yarn_classic_auth", "Protect-EsLine", '"//reg.corp/:_authToken" "CanaryYarnTok"', ("CanaryYarnTok",),
          ('"//reg.corp/:_authToken"',)),
)

JSON_NESTED = "\n".join([
    "{",
    '    "config": {',
    '        "github-oauth": {',
    f'            "github.com": "{HEX40}"',
    "        },",
    '        "secure-http": true',
    "    }",
    "}",
])
YAML_NESTED = "\n".join([
    "npmScopes:",
    "  corp:",
    '    npmRegistryServer: "https://npm.corp.example"',
    '    npmAuthToken: "abc123tok"',
    "github-oauth:",
    "  github.com: 0123456789abcdef",
    "other: kept",
])

TEXT_CASES = (
    _gone("json_block", "Protect-EsText", JSON_NESTED, (HEX40,), ('"secure-http": true', '"github-oauth": {')),
    _gone("yaml_block", "Protect-EsText", YAML_NESTED, ("abc123tok", "0123456789abcdef"),
          ("other: kept", "npmRegistryServer", "https://npm.corp.example")),
    _exact("pem_text", "Protect-EsText", "key:\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----",
           "<redacted: private key>"),
    # Review 2026-11-11, findings 5 and 12.
    _exact("userinfo_in_text", "Protect-EsText", "use bob:Hunter2pw@proxy.corp:3128 now", f"use bob:{PH}@proxy.corp:3128 now"),
    _gone("json_escaped_quote_text", "Protect-EsText", '{"password": "a\\"b\\"Sup3rS3cret", "x": 1}', ("Sup3rS3cret",),
          ('"x": 1',)),
    # Second review 2026-11-11.
    _gone("escaped_json_text", "Protect-EsText", 'cfg: {\\"token\\":\\"abc123secret\\"} end', ("abc123secret",), (" end",)),
    _exact("userinfo_lines_text", "Protect-EsText", "proxies:\n- svc:pw@proxy.corp:8080\nsvc:pw@proxy.corp:8080",
           f"proxies:\n- svc:{PH}@proxy.corp:8080\nsvc:{PH}@proxy.corp:8080"),
    # Security review 2026-11-12: multi-line values.
    _gone("yaml_block_literal", "Protect-EsText", "password: |\n  CanaryBlockPw\nother: kept", ("CanaryBlockPw",), ("other: kept",)),
    _gone("yaml_block_folded", "Protect-EsText", "token: >-\n  CanaryFoldTok\n  more\nother: kept", ("CanaryFoldTok",),
          ("other: kept",)),
    _gone("toml_triple_quote", "Protect-EsText", 'password = """\nCanaryTriplePw\n"""\nname = "x"', ("CanaryTriplePw",),
          ('name = "x"',)),
    _gone("xml_element_multiline", "Protect-EsText", "<password>\n  CanaryXmlPw\n</password>\n<user>bob</user>",
          ("CanaryXmlPw",), ("<user>bob</user>",)),
)

COMMAND_CASES = (
    _gone("cmd_windows_option", "Protect-EsCommandLine", "tool.exe /password:hunter2 /user:bob", ("hunter2",), ("/user:bob",)),
    _exact("cmd_curl_user", "Protect-EsCommandLine", "curl -u admin:hunter2 https://x", f"curl -u admin:{PH} https://x"),
    _gone("cmd_options", "Protect-EsCommandLine", 'app --pass hunter2 --passphrase "two words" --key k123 --auth a456',
          ("hunter2", "two words", "k123", "a456"), ("app ",)),
    _gone("cmd_headers", "Protect-EsCommandLine", 'curl -H "X-Api-Key: abc123" -H "Accept: text/plain"',
          ("abc123",), ("Accept: text/plain",)),
    _gone("cmd_java_props", "Protect-EsCommandLine", "java -Djavax.net.ssl.keyStorePassword=hunter2 -jar app.jar",
          ("hunter2",), ("-jar app.jar",)),
    _exact("cmd_service", "Protect-EsCommandLine", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
           "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
    _exact("cmd_path_with_key", "Protect-EsCommandLine", "/opt/keycloak/bin/kc.sh start --http-port 8080",
           "/opt/keycloak/bin/kc.sh start --http-port 8080"),
    # tool_options: password options of known tools (case-sensitive options).
    _gone("tool_mysql_attached", "Protect-EsCommandLine", "mysql -uroot -pS3cret -P 3306 db", ("S3cret",),
          ("-P 3306", "-uroot", " db")),
    _exact("tool_mysql_port_kept", "Protect-EsCommandLine", "mysql -P 3306 -h db", "mysql -P 3306 -h db"),
    _exact("tool_sshpass", "Protect-EsCommandLine", "sshpass -p S3cret ssh host", f"sshpass -p {PH} ssh host"),
    _exact("tool_redis_path", "Protect-EsCommandLine", "/usr/bin/redis-cli -h r1 -a S3cret ping",
           f"/usr/bin/redis-cli -h r1 -a {PH} ping"),
    _exact("tool_sqlcmd_quoted_exe", "Protect-EsCommandLine", '"C:\\Tools\\SQLCMD.EXE" -S db -U sa -P S3cret',
           f'"C:\\Tools\\SQLCMD.EXE" -S db -U sa -P {PH}'),
    _exact("tool_cron_line", "Protect-EsCommandLine", "0 2 * * * /usr/bin/mysqldump -pS3cret db > /tmp/x",
           f"0 2 * * * /usr/bin/mysqldump -p{PH} db > /tmp/x"),
    _exact("tool_quoted_value", "Protect-EsCommandLine", 'ldapsearch -x -w "two words" -b dc=x',
           f"ldapsearch -x -w {PH} -b dc=x"),
    _exact("tool_schtasks", "Protect-EsCommandLine", "schtasks /create /tn t /ru u /rp S3cret",
           f"schtasks /create /tn t /ru u /rp {PH}"),
    _exact("tool_name_inside_word", "Protect-EsCommandLine", "myazure -p 8080", "myazure -p 8080"),
    _exact("tool_option_alone", "Protect-EsCommandLine", "mysql -u root -p -h db", f"mysql -u root -p {PH} db"),
    _exact("tool_attached_quoted", "Protect-EsCommandLine", 'mysql -p"a b" db', f"mysql -p{PH} db"),
    _exact("tool_az_cmd", "Protect-EsCommandLine", '"C:\\CLI\\wbin\\az.cmd" login -u u -p S3cret',
           f'"C:\\CLI\\wbin\\az.cmd" login -u u -p {PH}'),
    _exact("tool_azure_cli_python", "Protect-EsCommandLine", "python.exe -IBm azure.cli login -u u -p S3cret",
           f"python.exe -IBm azure.cli login -u u -p {PH}"),
    _exact("tool_slash_option_any_case", "Protect-EsCommandLine", "schtasks /S h /U u /Rp S3cret",
           f"schtasks /S h /U u /Rp {PH}"),
    _exact("tool_upper_case_name", "Protect-EsCommandLine", "MYSQL.EXE -pS3cret", f"MYSQL.EXE -p{PH}"),
    _exact("tool_after_and", "Protect-EsCommandLine", "cd x && mysqldump -pS3cret db", f"cd x && mysqldump -p{PH} db"),
    _exact("tool_already_redacted", "Protect-EsCommandLine", f"mysql -p{PH} db", f"mysql -p{PH} db"),
    # Review 2026-11-11, finding 5: user:password@host without a scheme; user@host:path is not a credential.
    _exact("userinfo_option", "Protect-EsCommandLine", "curl -x bob:pw4Secret@proxy:3128 https://x",
           f"curl -x bob:{PH}@proxy:3128 https://x"),
    _exact("userinfo_domain_user_cmd", "Protect-EsCommandLine", "curl -x CORP\\jdoe:Secr3t@proxy.corp:8080 https://x",
           f"curl -x CORP\\jdoe:{PH}@proxy.corp:8080 https://x"),
    _exact("scp_target_kept", "Protect-EsCommandLine", "scp f.txt deploy@build.corp:/srv/x", "scp f.txt deploy@build.corp:/srv/x"),
    _gone("image_digest_kept", "Protect-EsCommandLine", f"docker pull docker.io/library/alpine:3.18@sha256:{'0' * 64}", (),
          ("docker.io/library/alpine:3.18@sha256:",)),
    # Finding 12: *AUTHORIZATION keys, values that only start with a redacted token.
    _gone("env_http_authorization", "Protect-EsCommandLine", "env HTTP_AUTHORIZATION=abcdef123456 app", ("abcdef123456",),
          ("env ", " app")),
    _gone("conn_string_token_then_rest", "Protect-EsCommandLine", f"app Server=x;Password=ghp_{'C' * 36}!Rest0fSecret",
          ("Rest0fSecret", "ghp_"), ("app Server=x;Password=",)),
    # Second review 2026-11-11.
    _gone("escaped_json_in_cmd", "Protect-EsCommandLine", 'docker run -e CFG="{\\"password\\":\\"hunter2\\"}" img',
          ("hunter2",), ("docker run -e CFG=", " img")),
    _exact("userinfo_upn_cmd", "Protect-EsCommandLine", "curl -x john.doe@corp.com:S3cretPw@proxy.corp:8080 https://x",
           f"curl -x john.doe@corp.com:{PH}@proxy.corp:8080 https://x"),
    # Security review 2026-11-12: more password options (spec tool_options/option_words), curl -u attached.
    _gone("tool_docker_login", "Protect-EsCommandLine", "docker login -u bob -p CanaryDockerPw reg.corp", ("CanaryDockerPw",),
          ("reg.corp",)),
    _gone("tool_zip_password", "Protect-EsCommandLine", "zip -P CanaryZipPw out.zip f", ("CanaryZipPw",), ("out.zip",)),
    _gone("tool_7z_attached", "Protect-EsCommandLine", "7z x -pCanary7zPw a.7z", ("Canary7zPw",), ("a.7z",)),
    _gone("option_cookie", "Protect-EsCommandLine", "app --cookie CanaryCookie1 --x", ("CanaryCookie1",), ("--x",)),
    _gone("curl_user_attached", "Protect-EsCommandLine", "curl -ubob:CanaryCurlPw https://x", ("CanaryCurlPw",), ("https://x",)),
    # Security review 2026-11-12 (round 2): quoted values of curl -u, the shell idiom 'a'\''b c',
    # and an escaped quote inside an escaped-quoted JSON string.
    _gone("curl_user_value_single_quoted", "Protect-EsCommandLine", "curl --user bob:'Pa55Word9' http://x",
          ("Pa55Word9",), ("http://x",)),
    _gone("curl_user_value_double_quoted_space", "Protect-EsCommandLine", 'curl -u bob:"pa5s Wor9d" http://x',
          ("pa5s", "Wor9d"), ("http://x",)),
    _gone("curl_user_whole_arg_quoted_space", "Protect-EsCommandLine", 'curl --user "bob:pa5s Wor9d" http://x',
          ("pa5s", "Wor9d"), ("http://x",)),
    _gone("curl_user_doubled_single_quote", "Protect-EsCommandLine", "curl -u bob:'pa5s''Wor9d tail7' http://x",
          ("pa5s", "Wor9d", "tail7"), ("http://x",)),
    _gone("option_shell_escaped_single_quote", "Protect-EsCommandLine", "app --password 'Sec9a'\\''Sec9b Sec9c' --other x",
          ("Sec9a", "Sec9b", "Sec9c"), (" --other x",)),
    _gone("escaped_json_value_with_escaped_quote", "Protect-EsValue", '{\\"password\\":\\"Pa5s\\\\\\"Wor9d\\"}',
          ("Pa5s", "Wor9d"), ('{\\"password\\":',)),
)

NAMED_CASES = (
    Case("env_maven_opts", "Protect-EsNamedValue", ("MAVEN_OPTS", "-Dhttp.proxyPassword=hunter2 -Xmx1g"),
         gone=("hunter2",), kept=("-Xmx1g",), exact=False),
    Case("env_proxy_no_scheme", "Protect-EsNamedValue", ("HTTP_PROXY", "user:hunter2@proxy:8080"),
         expected=f"user:{PH}@proxy:8080"),
    Case("env_java_tool_options", "Protect-EsNamedValue", ("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStorePassword=changeit"),
         gone=("changeit",), exact=False),
    Case("env_pwd", "Protect-EsNamedValue", ("PWD", "C:\\work"), expected="C:\\work"),
    Case("env_secret_name", "Protect-EsNamedValue", ("sessionKey", "abc"), expected=PH),
    Case("env_sshpass", "Protect-EsNamedValue", ("SSHPASS", "S3cret"), expected=PH),
)

SECRET9 = "Secr3tNine9"

# PowerShell-only cases (the sh suite imports the tuples above, not this one). Review 2026-11-11,
# finding 9: escaped quotes in every quoted-value rule, values that only start with the placeholder,
# keys ending in AUTHORIZATION; and redaction applied twice gives the same text (it runs several
# passes: line, value, data safety net). Protect-Twice* are helpers of tests/ps/redaction_cases.ps1.
PS_CASES = (
    _gone("ps_pair_key_escaped_quote", "Protect-EsValue", f'Server=x;Pwd="ab\\"{SECRET9}";Database=y', (SECRET9,),
          ("Database=y",)),
    _gone("ps_cli_option_escaped_quote", "Protect-EsCommandLine", f'app --password "a\\"b {SECRET9}" --x', (SECRET9,),
          ("--x",)),
    _gone("ps_tool_option_escaped_quote", "Protect-EsCommandLine", f'mysql -p"a\\"b {SECRET9}" db', (SECRET9,), (" db",)),
    _gone("ps_single_quote_doubled", "Protect-EsValue", f"password: 'it''s {SECRET9}' next", (SECRET9,), ("password:",)),
    _gone("ps_camel_proxy_authorization", "Protect-EsValue", '"proxyAuthorization": "Basic Zm9vYmFyYmF6"',
          ("Zm9vYmFyYmF6",), ('"proxyAuthorization": "Basic ',)),
    _gone("ps_dash_authorization_header", "Protect-EsValue", "X-Authorization: abcdef123456", ("abcdef123456",),
          ("X-Authorization: ",)),
    _gone("ps_value_token_then_rest", "Protect-EsValue", f"password=ghp_{'D' * 36}!Rest0fSecret", ("Rest0fSecret", "ghp_"),
          ("password=",)),
    _exact("ps_placeholder_then_rest", "Protect-EsValue", f"pwd={PH}Rest0fSecret;Database=x", f"pwd={PH};Database=x"),
    _exact("ps_placeholder_at_end", "Protect-EsValue", f"password={PH}", f"password={PH}"),
    _exact("ps_placeholder_then_separator", "Protect-EsValue", f"Pwd={PH};", f"Pwd={PH};"),
    _exact("ps_twice_userinfo", "Protect-TwiceValue", "--proxy bob:pw4Secret@proxy:8080 --x", f"--proxy bob:{PH}@proxy:8080 --x"),
    _exact("ps_twice_at_in_password", "Protect-TwiceValue", "user:p@ss@proxy.corp:8080", f"user:{PH}@proxy.corp:8080"),
    _exact("ps_twice_pair", "Protect-TwiceValue", "Server=db;Pwd=a;b;Database=y", f"Server=db;Pwd={PH};Database=y"),
    _exact("ps_twice_json_escaped", "Protect-TwiceValue", '{"password":"a\\"b","x":1}', f'{{"password":"{PH}","x":1}}'),
    _exact("ps_twice_bearer", "Protect-TwiceValue", "Authorization: Bearer abcdefghijkl", f"Authorization: Bearer {PH}"),
    _exact("ps_twice_http_authorization", "Protect-TwiceValue", "HTTP_AUTHORIZATION=abcdef123456 x",
           f"HTTP_AUTHORIZATION={PH} x"),
    _exact("ps_twice_cmd_option", "Protect-TwiceCommandLine", 'app --password "a b" --user bob', f"app --password {PH} --user bob"),
    _exact("ps_twice_line", "Protect-TwiceLine", 'proxy = "bob:Hunter2pw@proxy.corp:3128"', f'proxy = "bob:{PH}@proxy.corp:3128"'),
    # Probe notes get the value rules: a git includeIf condition can hold a credentialed URL.
    _exact("ps_git_condition_note", "Protect-EsValue",
           "git include not read (condition hasconfig:remote.*.url:https://ci:HasPw55@git.corp.example/**): ~/hc.gitconfig",
           f"git include not read (condition hasconfig:remote.*.url:https://ci:{PH}@git.corp.example/**): ~/hc.gitconfig"),
    _gone("ps_git_condition_note_token", "Protect-EsValue",
          f"git include not read (condition hasconfig:remote.*.url:https://ghp_{'E' * 36}@github.com/**): x",
          ("ghp_",), ("@github.com/**): x",)),
    # .gemrc keys are Ruby symbols (":http_proxy:"): the leading colon does not hide the name.
    _exact("ps_gemrc_password_symbol", "Protect-EsLine", ":password: Gem5ecretPw", f":password: {PH}"),
    _exact("ps_gemrc_proxy_password_symbol", "Protect-EsLine", ":proxy_password: Gem5ecretPw", f":proxy_password: {PH}"),
    _exact("ps_gemrc_proxy_userinfo", "Protect-EsLine", ":http_proxy: http://gemuser:Gem5ecretPw@gemproxy.corp:3128",
           f":http_proxy: http://gemuser:{PH}@gemproxy.corp:3128"),
    # Round 4: escaped-quoted values (unterminated, single quotes, followed by more pairs), twice.
    _exact("ps_escaped_unterminated", "Protect-EsValue", 'password=\\"hunter2 rest', f'password=\\"{PH}'),
    _exact("ps_escaped_single_quotes", "Protect-EsValue", "{\\'password\\':\\'hunter2\\'}", f"{{\\'password\\':\\'{PH}\\'}}"),
    _exact("ps_escaped_then_next_pair", "Protect-EsValue", '{\\"password\\":\\"a,b c\\",\\"user\\":\\"bob\\"}',
           f'{{\\"password\\":\\"{PH}\\",\\"user\\":\\"bob\\"}}'),
    _exact("ps_twice_escaped_json", "Protect-TwiceValue", '{\\"password\\":\\"hunter2\\"}', f'{{\\"password\\":\\"{PH}\\"}}'),
    _exact("ps_twice_escaped_pair_key", "Protect-TwiceValue", 'Pwd=\\"a b\\";Database=y', f'Pwd=\\"{PH}\\";Database=y'),
    _exact("ps_twice_escaped_authorization", "Protect-TwiceValue", '{\\"Authorization\\":\\"Bearer abcdefghij\\"}',
           f'{{\\"Authorization\\":\\"Bearer {PH}\\"}}'),
    _exact("ps_twice_upn_user", "Protect-TwiceValue", "john.doe@corp.com:S3cretPw@proxy.corp:8080",
           f"john.doe@corp.com:{PH}@proxy.corp:8080"),
    # Round 5: escaped-quoted option values (\\"...\\" holding spaces) for option and tool-option rules.
    _exact("ps_escaped_option_unterminated", "Protect-EsCommandLine", 'app --password=\\"hunter two', f'app --password=\\"{PH}'),
    _exact("ps_escaped_option_single_quotes", "Protect-EsCommandLine", "app --token \\'a b\\' --x", f"app --token \\'{PH}\\' --x"),
    _exact("ps_twice_escaped_option", "Protect-TwiceCommandLine", 'app --password=\\"hunter two\\" --x', f'app --password=\\"{PH}\\" --x'),
    _exact("ps_twice_escaped_tool_option", "Protect-TwiceCommandLine", 'mysql -p\\"two words\\" db', f"mysql -p{PH} db"),
    _exact("ps_escaped_tool_option_spaced", "Protect-EsCommandLine", 'mysql -p \\"two words\\" db', f"mysql -p {PH} db"),
)

# Bare userinfo beyond its bounds (user 1-128, password 1-256): the whole token goes (spec/redaction.toml).
# Promoted from the ps hardening test; the Twice cases check a second pass changes nothing.
LONG_USERINFO_CASES = (
    _exact("long_password_userinfo", "Protect-EsValue", "via bob:" + "p" * 300 + "@host.corp:8080 end", f"via {PH} end"),
    _exact("long_password_userinfo_twice", "Protect-TwiceValue", "via bob:" + "p" * 300 + "@host.corp:8080 end", f"via {PH} end"),
    _exact("long_password_userinfo_line", "Protect-TwiceLine", "proxy = bob:" + "p" * 300 + "@host.corp:8080", f"proxy = {PH}"),
    _exact("long_password_userinfo_cmd", "Protect-TwiceCommandLine", "app bob:" + "p" * 300 + "@host.corp x", f"app {PH} x"),
    _exact("long_user_userinfo", "Protect-EsValue", "via " + "u" * 200 + ":pw9Secret@host.corp end", f"via {PH} end"),
    _exact("long_password_at_in_password", "Protect-EsValue", "via bob:" + "p" * 150 + "@" + "q" * 150 + "@host end",
           f"via {PH} end"),
    _exact("userinfo_bounds_edge_stays_normal", "Protect-EsValue", "via bob:" + "p" * 256 + "@host.corp end",
           f"via bob:{PH}@host.corp end"),
    _exact("image_digest_stays", "Protect-EsValue", "image:tag@sha256:" + "a" * 64 + " x", "image:tag@sha256:" + "a" * 64 + " x"),
)

# Hardening round 2026-11-15 (redaction.toml LINE RULES xml / TEXT RULES multi-line): CDATA and
# nested markup, namespace prefixes, "/" in attributes, content that starts on the tag line.
XML_CASES = (
    _exact("xml_cdata", "Protect-EsLine", "<password><![CDATA[s3cret]]></password>", f"<password>{PH}</password>"),
    _exact("xml_ns_prefix", "Protect-EsLine", "<ns:password>s3cret</ns:password>", f"<ns:password>{PH}</ns:password>"),
    _exact("xml_slash_in_attribute", "Protect-EsLine", '<password xmlns="http://x/y">s3cret</password>',
           f'<password xmlns="http://x/y">{PH}</password>'),
    _exact("xml_unclosed_content", "Protect-EsLine", "<password>s3cret", f"<password>{PH}"),
    _exact("xml_unclosed_content_mid_line", "Protect-EsLine", "usage: tool <token> [opts]",
           f"usage: tool <token>{PH}"),
    _exact("xml_self_closing_kept", "Protect-EsLine", "<token/> <token /> <password a=\"b/c\"/>",
           "<token/> <token /> <password a=\"b/c\"/>"),
    _exact("xml_empty_element", "Protect-EsLine", "<password></password>", f"<password>{PH}</password>"),
    _exact("xml_text_content_spans_lines", "Protect-EsText",
           "<password>CanaryFirst\n  CanarySecond\n</password>\n<user>bob</user>",
           f"<password>{PH}\n  {PH}\n</password>\n<user>bob</user>"),
    _exact("xml_text_ns_open", "Protect-EsText", "<ns:clientSecret>\n  CanaryNs\n</ns:clientSecret>\n<x>1</x>",
           f"<ns:clientSecret>\n  {PH}\n</ns:clientSecret>\n<x>1</x>"),
    _exact("xml_text_attr_slash_open", "Protect-EsText", '<password xmlns="http://a/b">\n  CanaryAttr\n</password>\nok',
           f'<password xmlns="http://a/b">\n  {PH}\n</password>\nok'),
    _exact("xml_text_cdata_spans_lines", "Protect-EsText",
           "  <password><![CDATA[\n  CanaryCdata\n  ]]></password>\nafter",
           f"  <password>{PH}\n  {PH}\n  {PH}</password>\nafter"),
    _exact("xml_text_mid_line_tag_does_not_open", "Protect-EsText", "usage: tool <token> [opts]\nnext line kept",
           f"usage: tool <token>{PH}\nnext line kept"),
    # Review round 2026-11-15: prefix fallback, the element's own closing tag, upper case, the first
    # unclosed tag decides, no ">" on the line, hostile lines.
    _gone("xml_prefix_is_element", "Protect-EsLine", "<password:x>CanarySecret</password:x>", ("CanarySecret",)),
    _gone("xml_qname_with_secret_local_part_only", "Protect-EsLine", "<password:hunter2>", ("hunter2",)),
    _exact("xml_text_prefix_then_element", "Protect-EsText", "<token:password>\n  CanaryTP\n</token:password>\nafter",
           f"<token:password>\n  {PH}\n</token:password>\nafter"),
    _exact("xml_own_close_tag_nested", "Protect-EsLine", "<password>a</b>CanaryNested</password> <x>1</x>",
           f"<password>{PH}</password> <x>1</x>"),
    _exact("xml_own_close_tag_cdata", "Protect-EsLine", "<password><![CDATA[x</y]]>CanaryZ</password>",
           f"<password>{PH}</password>"),
    _exact("xml_upper_case", "Protect-EsLine", "<PASSWORD>abc</PASSWORD>", f"<PASSWORD>{PH}</PASSWORD>"),
    _exact("xml_text_upper_case_prefix", "Protect-EsText", "<NS:Token>\n  CanaryUp\n</NS:Token>\nok",
           f"<NS:Token>\n  {PH}\n</NS:Token>\nok"),
    _exact("xml_text_first_unclosed_tag_decides", "Protect-EsText", "see <token> and <password>\nnext kept",
           f"see <token>{PH}\nnext kept"),
    _exact("xml_no_gt_on_line", "Protect-EsLine", '<password type="x"', '<password type="x"'),
    _exact("xml_hostile_lt_run", "Protect-EsLine", "<" * 100000, "<" * 100000),
    _exact("xml_hostile_open_run", "Protect-EsLine", "<password" * 10000, "<password" * 10000),
    # Security review 2026-11-15: rescanning after a multi-line close, comments, start tags over
    # several lines, ">" inside quoted attribute values.
    _gone("xml_text_rescan_after_close", "Protect-EsText",
          "<password>\nq\nabc</password><token>CanaryAfter1</token> password=CanaryHunt1",
          ("CanaryAfter1", "CanaryHunt1"), ("</password><token>",)),
    _gone("xml_text_reopen_on_close_line", "Protect-EsText", "<password>\nq\n</password><password>\nCanaryReopen2\n</password>",
          ("CanaryReopen2",)),
    _exact("xml_close_in_comment", "Protect-EsLine", "<password>a<!-- </password> -->CanaryCmt3</password>",
           f"<password>{PH}</password>"),
    _gone("xml_text_close_in_comment", "Protect-EsText", "<password>\n<!-- </password> -->\nCanaryCmt4\n</password>\nafter",
          ("CanaryCmt4",), ("after",)),
    _gone("xml_text_split_start_tag", "Protect-EsText",
          '<password\n  xmlns:xsi="x"\n  xsi:nil="false">CanarySplit5</password>\nafter',
          ("CanarySplit5",), ("after", 'xsi:nil="false">')),
    _gone("xml_text_split_start_tag_multiline", "Protect-EsText", '<password\n  a="1">\n  CanarySplit6\n</password>\nok',
          ("CanarySplit6",), ("ok",)),
    _exact("xml_text_split_start_tag_abandoned", "Protect-EsText", "<token\n<other>keep7</other>",
           "<token\n<other>keep7</other>"),
    _exact("xml_gt_in_double_quotes", "Protect-EsLine", '<password a="x/>y">CanaryQ8</password>',
           f'<password a="x/>y">{PH}</password>'),
    _exact("xml_gt_in_single_quotes", "Protect-EsLine", "<password a='1>2'>CanaryQ9</password>",
           f"<password a='1>2'>{PH}</password>"),
)

ALL_CASES = NAME_CASES + VALUE_CASES + LINE_CASES + TEXT_CASES + COMMAND_CASES + NAMED_CASES + LONG_USERINFO_CASES + XML_CASES + PS_CASES

# sh-only cases: values the probes of envscan.sh produce.
SH_CASES = (
    Case("sh_env_proxy_url", "Protect-EsNamedValue", ("https_proxy", "http://u:pw-123@proxy.corp:3128"),
         expected=f"http://u:{PH}@proxy.corp:3128"),
    Case("sh_git_insteadof_key", "Protect-EsValue", ("url.https://u:tok123456@git.corp/.insteadof",),
         expected=f"url.https://u:{PH}@git.corp/.insteadof"),
    Case("sh_npmrc_authtoken", "Protect-EsLine", ("//npm.corp/repo/:_authToken=abc123",),
         expected=f"//npm.corp/repo/:_authToken={PH}"),
    Case("sh_pip_index", "Protect-EsLine", ("index-url = https://builder:pw1@pypi.corp/simple",),
         expected=f"index-url = https://builder:{PH}@pypi.corp/simple"),
    Case("sh_crontab", "Protect-EsCommandLine", ("*/5 * * * * /opt/x/run --api-key k3y999 >/dev/null",),
         gone=("k3y999",), kept=("*/5 * * * * /opt/x/run",), exact=False),
    Case("sh_ps_args", "Protect-EsCommandLine", ("mysql -uroot -pS3cr3t --password=S3cr3t db",),
         gone=("--password=S3cr3t",), kept=("mysql",), exact=False),
    Case("sh_yaml_dash_block", "Protect-EsText", ("tokens:\n  - tok-aaaa1111\n  - tok-bbbb2222\nname: x",),
         gone=("tok-aaaa1111", "tok-bbbb2222"), kept=("name: x", "tokens:"), exact=False),
    Case("sh_plain_line", "Protect-EsLine", ("deb http://archive.ubuntu.com/ubuntu jammy main",),
         expected="deb http://archive.ubuntu.com/ubuntu jammy main"),
    # name_suffixes "PASS"
    Case("sh_name_sshpass", "Test-EsSecretName", ("SSHPASS",), expected=True),
    Case("sh_name_dbpass", "Test-EsSecretName", ("DBPASS",), expected=True),
    Case("sh_name_mypass", "Test-EsSecretName", ("MyPass",), expected=True),
    Case("sh_name_passport", "Test-EsSecretName", ("PASSPORT_URL",), expected=False),
    Case("sh_name_askpass", "Test-EsSecretName", ("SUDO_ASKPASS",), expected=False),
    # unquoted run: separators belong to the value only before a value character that does not
    # start another key
    Case("sh_run_a_b", "Protect-EsValue", ("Pwd=a;b",), expected=f"Pwd={PH}"),
    Case("sh_run_trailing", "Protect-EsValue", ("Pwd=abc;",), expected=f"Pwd={PH};"),
    Case("sh_run_double_sep", "Protect-EsValue", ("token=abc;;def",), expected=f"token={PH}"),
    Case("sh_run_then_space", "Protect-EsValue", ("DB_PASS=Hun,ter2 next",), expected=f"DB_PASS={PH} next"),
    Case("sh_run_sep_space_key", "Protect-EsValue", ("{user: a, password: b, port: 1}",),
         expected=f"{{user: a, password: {PH}, port: 1}}"),
    Case("sh_run_amp_query", "Protect-EsValue", ("https://h/x?password=a&b&user=u",),
         expected=f"https://h/x?password={PH}&user=u"),
    Case("sh_run_env_cmd", "Protect-EsCommandLine", ("docker run -e DB_PASS=Hun,ter2 -e X=1 img",),
         expected=f"docker run -e DB_PASS={PH} -e X=1 img"),
    # tool options
    Case("sh_tool_mongo", "Protect-EsCommandLine", ("mongosh -u admin -p S3cret --host db",),
         expected=f"mongosh -u admin -p {PH} --host db"),
    Case("sh_tool_smbclient", "Protect-EsCommandLine", ("smbclient //srv/share -U user%S3cret",),
         expected=f"smbclient //srv/share -U {PH}"),
    Case("sh_tool_exe_attached", "Protect-EsCommandLine", ('"C:\\mysql\\bin\\mysql.exe" -uroot -p"two words"',),
         expected=f'"C:\\mysql\\bin\\mysql.exe" -uroot -p{PH}'),
    Case("sh_tool_sshpass_cron", "Protect-EsCommandLine", ("*/5 * * * * sshpass -p S3cret rsync a b:",),
         expected=f"*/5 * * * * sshpass -p {PH} rsync a b:"),
    Case("sh_tool_after_semicolon", "Protect-EsCommandLine", ("cd /x;redis-cli -a S3cret ping",),
         expected=f"cd /x;redis-cli -a {PH} ping"),
    Case("sh_tool_option_at_end", "Protect-EsCommandLine", ("mysql -p",), expected="mysql -p"),
    Case("sh_tool_not_program", "Protect-EsCommandLine", ("notmysql -pXYZ -P 1",), expected="notmysql -pXYZ -P 1"),
    Case("sh_tool_suffix_word", "Protect-EsCommandLine", ("mysql-workbench -pXYZ",), expected="mysql-workbench -pXYZ"),
    Case("sh_tool_ldap_case", "Protect-EsCommandLine", ("LDAPSEARCH -W -w S3cret",), expected=f"LDAPSEARCH -W -w {PH}"),
    # refined unquoted run: every separator , ; & # } ] ) " ' < > | continues before a value char
    Case("sh_run_paren_inside", "Protect-EsValue", ("password=ab)cd next",), expected=f"password={PH} next"),
    Case("sh_run_paren_after", "Protect-EsValue", ("(token=abc) && x",), expected=f"(token={PH}) && x"),
    Case("sh_run_json_unquoted", "Protect-EsValue", ('{"password":abc,"user":"x"}',),
         expected=f'{{"password":{PH},"user":"x"}}'),
    # a second pass over redacted text changes nothing
    Case("sh_rerun_pair", "Protect-EsValue", (f"password={PH};Database=x",), expected=f"password={PH};Database=x"),
    Case("sh_rerun_pairkey", "Protect-EsValue", (f"Server=db;Pwd={PH}",), expected=f"Server=db;Pwd={PH}"),
    Case("sh_rerun_line", "Protect-EsLine", (f"password: {PH}",), expected=f"password: {PH}"),
    Case("sh_rerun_cmd", "Protect-EsCommandLine", (f"mysql -p{PH} --password={PH} db",),
         expected=f"mysql -p{PH} --password={PH} db"),
    # refined tool options: .cmd/.bat/.com names, case-insensitive "/" options, azure.cli
    Case("sh_tool_azure_cli", "Protect-EsCommandLine", ("python -IBm azure.cli login -u x -p S3cret",),
         expected=f"python -IBm azure.cli login -u x -p {PH}"),
    Case("sh_tool_cmd_suffix", "Protect-EsCommandLine", ("C:\\bin\\sshpass.cmd -p S3cret ssh h",),
         expected=f"C:\\bin\\sshpass.cmd -p {PH} ssh h"),
    Case("sh_tool_slash_option_case", "Protect-EsCommandLine", ("SCHTASKS /Create /RU u /rp S3cret",),
         expected=f"SCHTASKS /Create /RU u /rp {PH}"),
    # review 2026-11-11, finding 5: scheme-less user:password@host inside text
    Case("sh_userinfo_at_in_password", "Protect-EsValue", ("user:p@ss@proxy.corp:8080",),
         expected=f"user:{PH}@proxy.corp:8080"),
    Case("sh_userinfo_env_cmd", "Protect-EsCommandLine", ("env https_proxy=bob:pw9Secret@proxy.corp:3128 app",),
         expected=f"env https_proxy=bob:{PH}@proxy.corp:3128 app"),
    Case("sh_userinfo_xml", "Protect-EsLine", ("<proxy>bob:pw9Secret@proxy.corp:3128</proxy>",),
         expected=f"<proxy>bob:{PH}@proxy.corp:3128</proxy>"),
    Case("sh_userinfo_leading_space", "Protect-EsNamedValue", ("proxy", " bob:pw9Secret@proxy.corp:3128"),
         expected=f" bob:{PH}@proxy.corp:3128"),
    Case("sh_userinfo_two_in_list", "Protect-EsValue", ("a:pw1Secret@h1.corp,b:pw2Secret@h2.corp",),
         expected=f"a:{PH}@h1.corp,b:{PH}@h2.corp"),
    Case("sh_userinfo_ipv6_host", "Protect-EsValue", ("bob:pw9Secret@[fd00::1]:3128",),
         expected=f"bob:{PH}@[fd00::1]:3128"),
    Case("sh_userinfo_idempotent", "Protect-EsValue", (f"bob:{PH}@proxy.corp:3128",),
         expected=f"bob:{PH}@proxy.corp:3128"),
    Case("sh_image_digest_bare_kept", "Protect-EsCommandLine",
         ("docker pull alpine:3.18@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",),
         expected="docker pull alpine:3.18@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
    Case("sh_image_digest_digits_kept", "Protect-EsValue", ("alpine:3.18@sha256:" + "0" * 64,),
         expected="alpine:3.18@sha256:" + "0" * 64),
    Case("sh_rsync_target_kept", "Protect-EsCommandLine", ("rsync -a deploy@build.corp:/srv/x .",),
         expected="rsync -a deploy@build.corp:/srv/x ."),
    # finding 6: only a value that IS the placeholder is skipped; escaped quotes; *AUTHORIZATION keys
    Case("sh_value_placeholder_prefix", "Protect-EsValue", (f"password={PH}Rest0fSecret",), expected=f"password={PH}"),
    Case("sh_value_pairkey_placeholder_prefix", "Protect-EsValue", (f"Server=x;Pwd={PH}Rest0fSecret;Database=y",),
         expected=f"Server=x;Pwd={PH};Database=y"),
    Case("sh_value_placeholder_kept", "Protect-EsValue", (f"password={PH}",), expected=f"password={PH}"),
    Case("sh_value_placeholder_quoted_kept", "Protect-EsValue", (f'{{"password": "{PH}", "x": 1}}',),
         expected=f'{{"password": "{PH}", "x": 1}}'),
    Case("sh_value_json_escaped_quote", "Protect-EsValue", ('{"password":"a\\"Sup3rS3cret","x":1}',),
         expected=f'{{"password":"{PH}","x":1}}'),
    Case("sh_value_json_escaped_backslash", "Protect-EsValue", ('{"password":"abc\\\\","x":"y"}',),
         expected=f'{{"password":"{PH}","x":"y"}}'),
    Case("sh_value_pairkey_escaped_quote", "Protect-EsValue", ('Pwd="a\\"Sup3rS3cret";Database=y',),
         expected=f"Pwd={PH};Database=y"),
    Case("sh_cmd_option_escaped_quote", "Protect-EsCommandLine", ('app --password "a\\"b c" --x',),
         expected=f"app --password {PH} --x"),
    Case("sh_value_http_authorization", "Protect-EsValue", ("HTTP_AUTHORIZATION=abcdef123456",),
         expected=f"HTTP_AUTHORIZATION={PH}"),
    Case("sh_value_proxy_authorization_json", "Protect-EsValue", ('"proxy_authorization": "Zm9vYmFyYmF6"',),
         expected=f'"proxy_authorization": "{PH}"'),
    Case("sh_value_camel_authorization", "Protect-EsValue", ('{"proxyAuthorization":"Zm9vYmFyYmF6"}',),
         expected=f'{{"proxyAuthorization":"{PH}"}}'),
    Case("sh_value_authorization_scheme_kept", "Protect-EsValue", ("X_AUTHORIZATION: Bearer abcdefghijkl",),
         expected=f"X_AUTHORIZATION: Bearer {PH}"),
    Case("sh_value_authorization_word_kept", "Protect-EsValue", ('{"type": "authorization", "n": 1}',),
         expected='{"type": "authorization", "n": 1}'),
    # a pkg.sources note on a conditional git include: the condition can hold a credentialed URL
    Case("sh_git_include_note_hasconfig", "Protect-EsValue",
         ("git include not read (condition hasconfig:remote.*.url:https://bob:pw9Secret@git.corp/**): ~/w.gitconfig",),
         expected=f"git include not read (condition hasconfig:remote.*.url:https://bob:{PH}@git.corp/**): ~/w.gitconfig"),
    Case("sh_git_include_note_brief_line", "Protect-EsLine",
         ("- pkg.sources: partial - git include not read (condition hasconfig:remote.*.url:https://bob:pw9Secret@git.corp/**): ~/w",),
         expected=f"- pkg.sources: partial - git include not read (condition hasconfig:remote.*.url:https://bob:{PH}@git.corp/**): ~/w"),
    # .gemrc keys are Ruby symbols (":http_proxy:"): the leading colon does not hide the name
    Case("sh_gemrc_password_symbol", "Protect-EsLine", (":password: Gem5ecretPw",), expected=f":password: {PH}"),
    Case("sh_gemrc_proxy_password_symbol", "Protect-EsLine", (":proxy_password: Gem5ecretPw",),
         expected=f":proxy_password: {PH}"),
    Case("sh_gemrc_proxy_userinfo", "Protect-EsLine", (":http_proxy: http://gemuser:Gem5ecretPw@gemproxy.corp:3128",),
         expected=f":http_proxy: http://gemuser:{PH}@gemproxy.corp:3128"),
    # second review 2026-11-11, A: escaped quotes inside a string (JSON in a value, shell arguments)
    Case("sh_escaped_single_quotes", "Protect-EsValue", ("{\\'token\\':\\'abc123\\'}",),
         expected=f"{{\\'token\\':\\'{PH}\\'}}"),
    Case("sh_escaped_value_unterminated", "Protect-EsValue", ('password=\\"hunter two',),
         expected=f'password=\\"{PH}'),
    Case("sh_escaped_json_idempotent", "Protect-EsValue", (f'{{\\"password\\":\\"{PH}\\"}}',),
         expected=f'{{\\"password\\":\\"{PH}\\"}}'),
    Case("sh_escaped_pairkey", "Protect-EsValue", ('Server=x;Pwd=\\"a b\\";Database=y',),
         expected=f'Server=x;Pwd=\\"{PH}\\";Database=y'),
    Case("sh_escaped_json_two_keys", "Protect-EsValue", ('{\\"user\\":\\"bob\\",\\"token\\":\\"t0k en\\",\\"n\\":1}',),
         expected=f'{{\\"user\\":\\"bob\\",\\"token\\":\\"{PH}\\",\\"n\\":1}}'),
    Case("sh_escaped_proxy_authorization_basic", "Protect-EsValue", ('{\\"Proxy-Authorization\\":\\"Basic Zm9vOmJhcg==\\"}',),
         gone=("Zm9vOmJhcg",), kept=('{\\"Proxy-Authorization\\":',), exact=False),
    Case("sh_escaped_option_value", "Protect-EsCommandLine", ('app --password=\\"hunter two\\" --x',),
         expected=f'app --password=\\"{PH}\\" --x'),
    Case("sh_escaped_option_value_space", "Protect-EsCommandLine", ('app --token \\"a b\\" --x',),
         expected=f'app --token \\"{PH}\\" --x'),
    Case("sh_escaped_tool_option", "Protect-EsCommandLine", ('mysql -p\\"two words\\" db',),
         expected=f"mysql -p{PH} db"),
    # F: user names with "@" (UPN) and # ? or a backslash after the host, also inside escaped JSON
    Case("sh_userinfo_in_escaped_json", "Protect-EsValue", ('{\\"proxy\\":\\"bob:pw9Secret@proxy.corp:3128\\"}',),
         expected=f'{{\\"proxy\\":\\"bob:{PH}@proxy.corp:3128\\"}}'),
    Case("sh_userinfo_upn_env", "Protect-EsNamedValue", ("https_proxy", "john.doe@corp.com:S3cretPw@proxy.corp:8080"),
         expected=f"john.doe@corp.com:{PH}@proxy.corp:8080"),
    Case("sh_userinfo_upn_scp_kept", "Protect-EsCommandLine", ("scp f john.doe@corp.com@build.corp:/srv/x",),
         expected="scp f john.doe@corp.com@build.corp:/srv/x"),
)

SHARED_CASES = (NAME_CASES + VALUE_CASES + LINE_CASES + TEXT_CASES + COMMAND_CASES + NAMED_CASES + LONG_USERINFO_CASES
                + XML_CASES)
PS_ONLY_CASES = PS_CASES

# Cases an implementation fails today although every implementation must pass them. Found by
# running each side's cases through the other implementation (tests/test_cross_redaction.py).
# The JScript and Go ports must pass all of them; shared_cases.py exports these as "pending".
KNOWN_DIVERGENCES: dict[str, dict[str, str]] = {}
