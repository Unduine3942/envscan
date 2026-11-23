# ============================================================== network mounts
# Which mount types and mount points are network (or autofs) mounts, from the scan-start mount
# table (12-mounts.sh): nothing on them is ever touched. Mount points keep a tab or a newline as
# the octal escapes of /proc/mounts (backslash 011, backslash 012; es_proc_mounts), and
# es_mount_text spells a path the same way before it is compared.

# ES_NET_FS (network filesystem types, space separated), ES_NET_FS_PREFIXES and ES_LOCAL_FUSE are
# generated from spec/policy.toml. ES_AWK_NETFS: es_isnet(type) for awk programs run with
# -v net="$ES_NET_FS" -v npre="$ES_NET_FS_PREFIXES" -v lfuse="$ES_LOCAL_FUSE" (the es_is_netfs rule)
ES_AWK_NETFS='function es_isnet(t,   i, n, P) { t = tolower(t); if (index(net, " " t " ") > 0) return 1; if (index(lfuse, " " t " ") > 0) return 0; n = split(npre, P, " "); for (i = 1; i <= n; i++) if (index(t, P[i]) == 1) return 1; return 0 }'

# es_netmnts_init -> ES_NETMNTS: the mount points of network and autofs file systems
# (newline-terminated lines) from the scan-start mount table. "/" is never listed: a network
# root file system is used as it is.
es_netmnts_init() {
  ES_NETMNTS=
  es_net_fs_extend
  es_local_fs_list
  if [ -s "$ES_TMP/mounts.tsv" ]; then
    ES_NETMNTS=$(awk -F '\t' -v net="$ES_NET_FS" -v npre="$ES_NET_FS_PREFIXES" -v lfuse="$ES_LOCAL_FUSE" -v lfs="$ES_LOCAL_FS" "$ES_AWK_NETFS"' $2 != "/" && (es_isnet($3) || (lfs != "" && index(lfs, " " $3 " ") == 0)) { print $2 }' "$ES_TMP/mounts.tsv")
    [ -n "${ES_NETMNTS:-}" ] && ES_NETMNTS="$ES_NETMNTS$ES_NL"
  fi
  es_win_netmnts
  es_os_netmnts
  return 0
}

# es_net_fs_extend: z/OS and IBM i network file system types that spec/policy.toml does not list
# (tier 2, unverified; nfs3 and dfs are in the spec); idempotent. The generated ES_NET_FS stays the
# only definition; es_is_netfs and ES_AWK_NETFS add the network_fs_prefixes rule.
es_net_fs_extend() {
  case $ES_NET_FS in *" qntc "*) return 0 ;; esac
  ES_NET_FS="${ES_NET_FS}qntc qfilesvr.400 qfilesvr automnt "
}

# es_local_fs_list -> ES_LOCAL_FS: on z/OS and IBM i only a file system type known to be local counts
# as local (fail closed: an unknown type, "unknown" included, is treated as a network mount); empty
# elsewhere. Tier 2, unverified: the IBM i names are the PASE mount command's vfs column as I know it.
es_local_fs_list() {
  case ${ES_OS:-} in
    zos) ES_LOCAL_FS=' zfs hfs tfs ' ;;
    os400) ES_LOCAL_FS=' udfs qsys root qopensys qdls qopt qlfs jfs jfs2 namefs procfs tmpfs cdrfs ' ;;
    *) ES_LOCAL_FS= ;;
  esac
}

# es_os_netmnts: network roots that no mount table lists. IBM i PASE shows /QNTC (Windows
# shares) and /QFileSvr.400 (other IBM i systems) as ordinary directories; nothing below them is
# ever touched.
es_os_netmnts() {
  case ${ES_OS:-} in
    os400) ES_NETMNTS="${ES_NETMNTS:-}/QNTC$ES_NL/QFileSvr.400$ES_NL" ;;
  esac
  return 0
}

# es_win_netmnts: Cygwin/MSYS list mapped network drives as ordinary drives; each letter under
# HKEY_CURRENT_USER\Network (read through /proc/registry, which only Cygwin and MSYS have)
# adds /cygdrive/<letter> and /<letter>, both cases, to ES_NETMNTS
es_win_netmnts() {
  es_wn_d="${ES_ROOT:-}/proc/registry/HKEY_CURRENT_USER/Network"
  [ -d "$es_wn_d" ] || return 0
  for es_wn_l in "$es_wn_d"/?; do
    es_wn_l=${es_wn_l##*/}
    case $es_wn_l in [ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]) ;; *) continue ;; esac
    es_wn_u=$(printf '%s' "$es_wn_l" | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    es_wn_w=$(printf '%s' "$es_wn_l" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
    ES_NETMNTS="${ES_NETMNTS:-}/cygdrive/$es_wn_w$ES_NL/cygdrive/$es_wn_u$ES_NL/$es_wn_w$ES_NL/$es_wn_u$ES_NL"
  done
  return 0
}

# es_mount_text PATH -> ES_MT: PATH spelled as the mount table spells mount points (a tab as the
# four characters backslash 011, a newline as backslash 012), so that such a path compares exactly
es_mount_text() {
  ES_MT=$1
  case $1 in *"$ES_TAB"*|*"$ES_NL"*) ;; *) return 0 ;; esac
  ES_MT=; es_mt_r=$1
  while :; do
    es_mt_t=${es_mt_r%%"$ES_TAB"*}; es_mt_n=${es_mt_r%%"$ES_NL"*}
    if [ "$es_mt_t" = "$es_mt_r" ] && [ "$es_mt_n" = "$es_mt_r" ]; then ES_MT=$ES_MT$es_mt_r; return 0; fi
    if [ "${#es_mt_t}" -lt "${#es_mt_n}" ]; then ES_MT="$ES_MT$es_mt_t\\011"; es_mt_r=${es_mt_r#*"$ES_TAB"}
    else ES_MT="$ES_MT$es_mt_n\\012"; es_mt_r=${es_mt_r#*"$ES_NL"}
    fi
  done
}

# es_on_netfs PATH: PATH (as text, nothing is touched) is a network/autofs mount point or below one
es_on_netfs() {
  case $1 in //[!/]*|"\\\\"*) return 0 ;; esac
  es_mount_text "$1"
  es_nf_r=${ES_NETMNTS:-}
  while [ -n "$es_nf_r" ]; do
    es_nf_m=${es_nf_r%%"$ES_NL"*}; es_nf_r=${es_nf_r#*"$ES_NL"}
    case $ES_MT in "$es_nf_m"|"$es_nf_m"/*) return 0 ;; esac
  done
  return 1
}

# es_netmnt_under DIR: a network/autofs mount point lies below DIR (a glob there could touch it)
es_netmnt_under() {
  es_mount_text "${1%/}"
  es_nf_r=${ES_NETMNTS:-}
  while [ -n "$es_nf_r" ]; do
    es_nf_m=${es_nf_r%%"$ES_NL"*}; es_nf_r=${es_nf_r#*"$ES_NL"}
    case $es_nf_m in "$ES_MT"/*) return 0 ;; esac
  done
  return 1
}

# es_mount_of PATH -> ES_MNT, ES_MFS, ES_MOPT from the mount table file $ES_TMP/mounts.tsv (the
# path reaches awk through the environment: -v would read its backslashes as escapes)
es_mount_of() {
  ES_MNT=; ES_MFS=; ES_MOPT=
  [ -s "$ES_TMP/mounts.tsv" ] || return 1
  es_resolve "$1"
  es_mount_text "$ES_RPATH"
  es_mo=$(ES_MO_P=$ES_MT awk -F '\t' '
    BEGIN { p = ENVIRON["ES_MO_P"] }
    { m = $2; if (m == "/" || p == m || index(p, m "/") == 1) { if (length(m) > best) { best = length(m); r = $2 "\t" $3 "\t" $4 } } }
    END { if (best) print r }' "$ES_TMP/mounts.tsv")
  [ -n "$es_mo" ] || return 1
  ES_MNT=${es_mo%%"$ES_TAB"*}; es_mo=${es_mo#*"$ES_TAB"}
  ES_MFS=${es_mo%%"$ES_TAB"*}; ES_MOPT=${es_mo#*"$ES_TAB"}
  return 0
}

# es_is_netfs TYPE: a mount of file system TYPE (any case) is a network mount: TYPE is in ES_NET_FS,
# or it starts with an ES_NET_FS_PREFIXES entry ("fuse.", also "fuse." itself: an empty subtype)
# and is not in ES_LOCAL_FUSE (all
# generated from spec/policy.toml; ES_AWK_NETFS is the same rule for awk)
es_is_netfs() {
  es_inf=$1
  case $es_inf in
    *[ABCDEFGHIJKLMNOPQRSTUVWXYZ]*) es_inf=$(printf '%s' "$es_inf" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz') ;;
  esac
  case $ES_NET_FS in *" $es_inf "*) return 0 ;; esac
  case $ES_LOCAL_FUSE in *" $es_inf "*) return 1 ;; esac
  for es_inp in $ES_NET_FS_PREFIXES; do
    case $es_inf in "$es_inp"*) return 0 ;; esac
  done
  return 1
}
