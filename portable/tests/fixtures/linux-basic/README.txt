ENVSCAN_ROOT fixture for tests/test_sh_fixtures.py: an Ubuntu 22.04 host on a corporate
network (proxy in /etc/environment, an APT cache in /etc/apt/apt.conf.d and a
Nexus pypi-proxy index URL that is not a proxy, internal DNS, full-tunnel VPN on tun0), running in a
cgroup v2 slice with memory/cpu/pids limits and low inotify / max_map_count settings.
Only files the sh scanner reads under ENVSCAN_ROOT are here; everything is synthetic.
