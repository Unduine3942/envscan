"""Proxy settings found by the NAME of the setting, never by "proxy" in a value: the cases both
implementations must agree on. Data only: tests/test_ps_proxy.py runs them through
envscan.ps1, tests/test_sh_proxy_parity.py through envscan.sh (src/sh/awk/proxy.awk).

A ConfigCase is one file of a spec/configs.toml entry: its mode, match and max_bytes apply, and
`expected` is that entry's proxy_urls. A GitCase is git config --list entries ("key=value") of
one origin, and `expected` the URLs of git's proxy settings. URLs are scheme://host[:port] in
lower case, in the order of the settings, each once; never userinfo, a path or a query. A bare
host:port is written as http://host:port; a bare host under a key ending in "proxy" gets :80. A
value without a scheme may start with user:password@ (pip, wget, /etc/environment): it is still a
proxy, never with its credentials. A bare host may be a single label (webproxy), but not a keyword
such as null, false, off or direct.
Exclusion lists (no_proxy, nonProxyHosts and the like) and Go's module settings (GOPROXY names a
module mirror, GONOPROXY its exclusions) are no HTTP proxies: they never give a proxy URL.
`endpoints`, when set, is the entry's urls (endpoint bases), which come from the raw text.
"""
from __future__ import annotations

from typing import NamedTuple, Optional


class ConfigCase(NamedTuple):
    name: str
    config_id: str
    text: str
    expected: tuple[str, ...]
    endpoints: Optional[tuple[str, ...]] = None


class GitCase(NamedTuple):
    name: str
    entries: tuple[str, ...]
    expected: tuple[str, ...]


CONFIG_CASES = (
    ConfigCase("npmrc_proxy_keys", "npmrc.user",
               "registry=https://nexus.corp/repository/npm-proxy/\n"
               "https-proxy=http://bob:pw@proxy.corp:8080/\n"
               "noproxy=.corp\n"
               "proxy = http://proxy.corp:3128\n",
               ("http://proxy.corp:8080", "http://proxy.corp:3128")),
    # The review finding: a Nexus repository named *-proxy is a registry, not a proxy.
    ConfigCase("npmrc_registry_named_proxy", "npmrc.user",
               "registry=https://nexus.corp/repository/npm-proxy/\n"
               "//nexus.corp/repository/npm-proxy/:_authToken=abc\n"
               "@corp:registry=https://nexus.corp/repository/npm-proxy-corp/\n",
               ()),
    ConfigCase("npmrc_crlf", "npmrc.user",
               "https-proxy=http://crlfproxy.corp:8080\r\nregistry=https://nexus.corp/repository/npm-proxy/\r\n",
               ("http://crlfproxy.corp:8080",)),
    ConfigCase("yarnrc_space_separated", "yarnrc",
               'registry "https://nexus.corp/repository/npm-proxy/"\n'
               'https-proxy "http://yarnproxy.corp:8080"\n',
               ("http://yarnproxy.corp:8080",)),
    ConfigCase("yarnrc_yml", "yarnrc",
               'npmRegistryServer: "https://nexus.corp/repository/npm-proxy/"\n'
               'httpProxy: "http://berryproxy.corp:3128"\n'
               'httpsProxy: "http://berryproxy.corp:3129"\n',
               ("http://berryproxy.corp:3128", "http://berryproxy.corp:3129")),
    ConfigCase("condarc_proxy_block", "condarc",
               "channel_alias: https://nexus.corp/repository/conda-proxy\n"
               "proxy_servers:\n"
               "  http: http://condaproxy.corp:8080\n"
               "  https: https://condaproxy.corp:8443\n"
               "ssl_verify: true\n"
               "channels:\n"
               "  - https://nexus.corp/repository/conda-proxy/main\n",
               ("http://condaproxy.corp:8080", "https://condaproxy.corp:8443")),
    ConfigCase("maven_proxy_block", "maven.settings",
               "<settings>\n"
               "  <!-- <proxy><host>old.corp</host></proxy> -->\n"
               "  <!--\n"
               "  <proxies><proxy><host>older.corp</host><port>1</port></proxy></proxies>\n"
               "  -->\n"
               "  <proxies>\n"
               "    <proxy>\n"
               "      <id>corp</id>\n"
               "      <protocol>http</protocol>\n"
               "      <host>mvnproxy.corp</host>\n"
               "      <port>8081</port>\n"
               "      <username>bob</username>\n"
               "      <password>pw</password>\n"
               "      <nonProxyHosts>localhost|*.corp</nonProxyHosts>\n"
               "    </proxy>\n"
               "    <proxy>\n"
               "      <protocol>HTTPS</protocol>\n"
               "      <host>mvnproxy2.corp</host>\n"
               "    </proxy>\n"
               "  </proxies>\n"
               "  <mirrors><mirror><url>https://nexus.corp/repository/maven-proxy/</url></mirror></mirrors>\n"
               "</settings>\n",
               ("http://mvnproxy.corp:8081", "https://mvnproxy2.corp")),
    ConfigCase("gradle_java_pair", "gradle.props",
               "systemProp.https.proxyHost=gradleproxy.corp\n"
               "systemProp.https.proxyPort=8443\n"
               "systemProp.https.proxyPassword=pw\n"
               "systemProp.http.proxyHost=gradlehttp.corp\n"
               "systemProp.http.nonProxyHosts=*.corp\n"
               "org.gradle.jvmargs=-Xmx2g\n",
               ("http://gradleproxy.corp:8443", "http://gradlehttp.corp:80")),
    ConfigCase("java_net_lines_mode", "java.net",
               "# java.net.useSystemProxies: see the documentation\n"
               "http.proxyHost=javaproxy.corp\n"
               "http.proxyPort=3128\n"
               "http.nonProxyHosts=localhost|127.*\n"
               "java.net.useSystemProxies=false\n"
               "socksProxyHost=javasocks.corp\n",
               ("http://javaproxy.corp:3128", "http://javasocks.corp:1080")),
    ConfigCase("nuget_add_keys", "nuget.user",
               '<?xml version="1.0" encoding="utf-8"?>\n'
               "<configuration>\n"
               "  <packageSources>\n"
               '    <add key="nuget-proxy" value="https://nexus.corp/repository/nuget-proxy/index.json" />\n'
               "  </packageSources>\n"
               "  <config>\n"
               '    <add key="http_proxy" value="http://nugetproxy.corp:8080" />\n'
               '    <add key="http_proxy.user" value="bob" />\n'
               '    <add key="http_proxy.password" value="pw" />\n'
               '    <add key="no_proxy" value="*.corp" />\n'
               "  </config>\n"
               "</configuration>\n",
               ("http://nugetproxy.corp:8080",)),
    ConfigCase("cargo_bare_host_port", "cargo",
               "[http]\n"
               'proxy = "cargoproxy.corp:8080"\n'
               "[source.crates-io]\n"
               'replace-with = "corp-proxy"\n'
               "[source.corp-proxy]\n"
               'registry = "sparse+https://nexus.corp/repository/cargo-proxy/"\n',
               ("http://cargoproxy.corp:8080",)),
    ConfigCase("pip_bare_host", "pip.user",
               "[global]\n"
               "# proxy = http://commented.corp:1\n"
               "proxy=pipproxy.corp\n"
               "index-url = https://nexus.corp/repository/pypi-proxy/simple\n",
               ("http://pipproxy.corp:80",)),
    ConfigCase("pip_credentialed_proxy", "pip.user",
               "[global]\n"
               "proxy = http://builder:S3cret@pipproxy.corp:3128  # corporate\n",
               ("http://pipproxy.corp:3128",)),
    ConfigCase("docker_daemon_json", "docker.daemon",
               "{\n"
               '  "proxies": {\n'
               '    "http-proxy": "http://dockerproxy.corp:3128",\n'
               '    "https-proxy": "http://dockerproxy.corp:3129",\n'
               '    "no-proxy": "*.corp"\n'
               "  },\n"
               '  "registry-mirrors": ["https://nexus.corp/repository/docker-proxy"]\n'
               "}\n",
               ("http://dockerproxy.corp:3128", "http://dockerproxy.corp:3129")),
    ConfigCase("bunfig_registry_named_proxy", "bunfig",
               "[install]\n"
               'registry = "https://nexus.corp/repository/npm-proxy/"\n',
               ()),
    ConfigCase("uv_index_named_proxy", "uv",
               "[[index]]\n"
               'url = "https://nexus.corp/repository/pypi-proxy/simple"\n'
               "default = true\n",
               ()),
    # GOPROXY is the Go module mirror (a registry), GONOPROXY its exclusions: no HTTP proxy, but
    # the mirror stays an endpoint.
    ConfigCase("go_env_module_proxy", "go.env",
               "GOPROXY=https://nexus.corp/repository/go-proxy/,direct\n"
               "GONOPROXY=nexus.corp:8081\n"
               "GOPRIVATE=*.corp\n",
               (), endpoints=("https://nexus.corp",)),
    # Exclusion lists name hosts, at times with a port or a scheme: never a proxy URL.
    ConfigCase("exclusion_keys", "npmrc.user",
               "noproxy=noproxy.corp:8080\n"
               "no-proxy=http://nexus.corp:8081\n"
               "NO_PROXY=nexus2.corp:8081\n"
               "proxy_bypass=bypass.corp:3128\n"
               "proxy-exclude=http://exclude.corp:3128\n"
               "no_proxies_on=noproxies.corp:8080\n"
               "nonProxies=http://nonproxies.corp:8080\n",
               ()),
    ConfigCase("maven_non_proxy_hosts", "maven.settings",
               "<settings>\n"
               "  <proxies>\n"
               "    <proxy>\n"
               "      <nonProxyHosts>nexus.corp:8081</nonProxyHosts>\n"
               "    </proxy>\n"
               "  </proxies>\n"
               "</settings>\n",
               ()),
    ConfigCase("java_non_proxy_hosts", "gradle.props",
               "systemProp.http.nonProxyHosts=nexus.corp:8081\n"
               "systemProp.https.nonProxyHosts=https://nexus.corp:8443\n",
               ()),
    ConfigCase("java_net_non_proxy_hosts", "java.net",
               "http.nonProxyHosts=nexus.corp:8081\n"
               "https.nonProxyHosts=nexus.corp:8443\n",
               ()),
    # RubyGems writes its settings as Ruby symbols (":http_proxy:"); user names and passwords
    # never come out.
    ConfigCase("gemrc_symbol_keys", "gemrc",
               "---\n"
               ":backtrace: false\n"
               ":sources:\n"
               "- https://nexus.corp/repository/rubygems-proxy/\n"
               ":http_proxy: http://gemuser:Gem5ecret@gemproxy.corp:3128\n"
               ":proxy_password: Gem5ecret\n"
               "gem: --no-document\n",
               ("http://gemproxy.corp:3128",), endpoints=("https://nexus.corp", "http://gemproxy.corp:3128")),
    ConfigCase("gemrc_proxy_disabled", "gemrc",
               ":http_proxy: :no_proxy\n",
               ()),
    # Second review 2026-11-11: user:password@ without a scheme, single-label hosts, keywords.
    ConfigCase("pip_userinfo_without_scheme", "pip.user",
               "[global]\n"
               "proxy = bob:S3cret@pipproxy.corp:3128\n"
               "[install]\n"
               "proxy = bob:S3cret@webproxy\n",
               ("http://pipproxy.corp:3128", "http://webproxy:80")),
    ConfigCase("environment_userinfo_address", "etc.environment",
               'http_proxy="bob:S3cret@10.0.0.5:8080"\n'
               "https_proxy=webproxy\n",
               ("http://10.0.0.5:8080", "http://webproxy:80")),
    ConfigCase("npmrc_proxy_keywords", "npmrc.user",
               "proxy=null\n"
               "https-proxy=false\n"
               "noproxy=intranet\n",
               ()),
    ConfigCase("apt_proxy_keywords", "apt.conf",
               'Acquire::http::Proxy "DIRECT";\n'
               'Acquire::https::Proxy "false";\n',
               ()),
)

GIT_CASES = (
    GitCase("git_proxy_keys", (
        "url.https://nexus.corp/repository/github-proxy/.insteadof=https://github.com/",
        "http.proxy=http://gitproxy.corp:3128",
        "http.https://internal.corp/.proxy=http://user:pw@scoped.corp:8080",
        "http.proxyauthmethod=basic",
        "remote.origin.url=https://nexus.corp/repository/git-proxy/repo.git",
        "remote.origin.proxy=socks5://sockproxy.corp",
    ), ("http://gitproxy.corp:3128", "http://scoped.corp:8080", "socks5://sockproxy.corp")),
    GitCase("git_bare_proxies", (
        "http.proxy=gitproxy.corp:3128",
        "http.https://other.corp/.proxy=othergit.corp",
    ), ("http://gitproxy.corp:3128", "http://othergit.corp:80")),
    GitCase("git_proxy_disabled", (
        "http.proxy=",
        "http.https://nexus.corp/repository/npm-proxy/.sslverify=false",
    ), ()),
    GitCase("git_userinfo_without_scheme", (
        "http.proxy=bob:S3cret@gitproxy.corp:3128",
        "http.https://other.corp/.proxy=webgit",
        "http.https://third.corp/.proxy=off",
    ), ("http://gitproxy.corp:3128", "http://webgit:80")),
)
