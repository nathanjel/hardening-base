#!/usr/bin/env bash
# Phase 0 inventory for hardening-base. READ-ONLY: it lists, shows and measures,
# and changes nothing on the system. Runs at the lowest CPU and IO priority; the
# slow parts (du, find) have time limits.
#
# Output: collected in a new root-only folder (/var/tmp/hb-inventory.*), then copied
# into ./out/ next to this script by the invoking user, with their own rights (root
# never writes into a folder that user controls), mode 0700; the root-only folder goes.
#
# Works on Fedora and Amazon Linux 2023, on bare metal or EC2, with microk8s,
# k3s, rke2, kubeadm or only a kubeconfig. Each section checks that its
# commands exist and says so when they don't.
#
# Deliberately NOT collected: password hashes; private keys (only their paths and
# modes); Kubernetes Secrets and Helm releases, not even listed (kubectl's table view
# still carries each object's annotations, where `kubectl apply` keeps a copy of a
# Secret's values, and Helm keeps each release, values included, in a Secret); EC2
# user-data and instance-role credentials; file names inside other users' homes;
# application/journal log content (only kernel warnings and sshd auth summaries).
# Printed as they are: configuration files (sudoers, sshd, sysctl, dnf, proxy server
# lines) and crontabs, so anything secret written into those lands in the report.
#
# Kubernetes: a kubeconfig can run programs (credential plugins). One the invoking
# user can change is only ever used as that user; root uses only microk8s and system
# kubeconfigs nobody but root can change (every folder on the way root's, no links,
# no group or other write, no ACL). --context or --kubeconfig pins the cluster: when it
# doesn't answer, nothing else is tried. Cluster queries are reads only (get).
#
# Usage:  sudo bash phase0/inventory.sh [--context NAME] [--kubeconfig PATH] [--no-k8s]
#   Default cluster: the current context of the first source that answers: the
#   invoking user's kubectl, then microk8s, then root's system kubeconfigs.
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo bash $0" >&2; exit 1; }

KCONTEXT="" KCONFIG="" NOK8S=""
while [ $# -gt 0 ]; do
  case "$1" in
    --context) KCONTEXT="${2:?}"; shift 2 ;;
    --kubeconfig) KCONFIG="${2:?}"; shift 2 ;;
    --no-k8s) NOK8S=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

renice -n 19 $$ >/dev/null 2>&1; ionice -c3 -p $$ >/dev/null 2>&1   # children inherit both

umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /var/tmp/hb-inventory.XXXXXX)" || exit 1   # root's own, 0700, until the handover
trap 'rm -rf "$OUT"' EXIT
MAIN="$OUT/inventory.txt"
: > "$MAIN"
T="timeout 90"
SLOW="timeout 300"
U="${SUDO_USER:-}"
UHOME="$( [ -n "$U" ] && getent passwd "$U" | cut -d: -f6 )"

exec 3>&1            # keep the terminal for progress
exec >>"$MAIN" 2>&1  # everything else goes to the report

sec() { printf '\n\n######## %s ########\n' "$*"; printf '  %s\n' "$*" >&3; }
hdr() { printf '\n$ %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
active() { systemctl is-active --quiet "$1" 2>/dev/null; }
# tofile NAME CMD... — long output goes to out/NAME, the report gets its line count
tofile() { local f="$OUT/$1"; shift; "$@" > "$f" 2>&1; echo "$(wc -l < "$f") lines in out/${f##*/}"; }
nocomment() { grep -vE '^\s*(#|;|$)' "$@"; }
# trusted PATH [dir] — only root can change PATH or any folder on the way to it: every part is root's,
# not a symlink, not writable by group or others, and carries no ACL. Root only reads or runs
# such files where their content matters (a kubeconfig can run programs).
trusted() {
  python3 -I -c '
import os, stat, sys
path = sys.argv[1]
if not os.path.isabs(path) or os.path.normpath(path) != path:
    sys.exit(1)
parts = path.split("/")[1:]
for i in range(len(parts) + 1):
    p = "/" + "/".join(parts[:i])
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        sys.exit(1)
    try:
        os.getxattr(p, "system.posix_acl_access", follow_symlinks=False)
        sys.exit(1)                                   # an ACL beyond the mode bits
    except OSError:
        pass
want = stat.S_ISDIR if sys.argv[2:] == ["dir"] else stat.S_ISREG
sys.exit(0 if want(st.st_mode) else 1)' "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
sec "system"
hdr "os-release";                  grep -E '^(NAME|VERSION|ID|PLATFORM_ID)=' /etc/os-release
[ -f /etc/amazon-linux-release ] && cat /etc/amazon-linux-release
hdr "date / uptime / kernel";      date; uptime; uname -a; cat /proc/cmdline
hdr "cpu / memory / swap";         nproc; free -h; swapon --show
hdr "installed kernels";           rpm -qa 'kernel*' --qf '%{INSTALLTIME} %{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' | awk '$2 ~ /^kernel([0-9.]+)?(-core)?$/' | sort -n | while read -r t n v; do echo "$(date -d "@$t" '+%F %R')  $n $v"; done; echo "running: $(uname -r)"
hdr "kernel live patching";        rpm -qa 'kpatch*' 'kernel-livepatch*' 2>&1; active kpatch && echo "kpatch active"
hdr "selinux";                     getenforce 2>&1; sestatus 2>&1 | head -12; [ -f /etc/selinux/config ] && nocomment /etc/selinux/config
hdr "crypto policy";               update-crypto-policies --show 2>&1
hdr "secure boot";                 mokutil --sb-state 2>/dev/null || echo "mokutil not available"
hdr "cloud-init";                  cloud-init status 2>/dev/null || echo "cloud-init not available"
hdr "python";                      ls -l /usr/bin/python3 /usr/bin/python3.* 2>/dev/null; python3 -V
hdr "hb already here?";            ls -ld /opt/hb /etc/hb 2>&1
hdr "failed units";                systemctl --failed --no-pager
hdr "enabled unit files";          systemctl list-unit-files --state=enabled --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
hdr "running services";            systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
hdr "processes by user (command names only)"; ps -eo user:20,comm --no-headers | sort | uniq -c | sort -rn | head -80
hdr "security and management agents (active?)"
for s in amazon-ssm-agent amazon-cloudwatch-agent auditd fapolicyd aide falcon-sensor crowdsec fail2ban osqueryd falco wazuh-agent; do
  systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . && echo "$s: $(systemctl is-active "$s" 2>&1)"
done

# ---------------------------------------------------------------------------
sec "cloud (EC2 instance metadata; never user-data or role credentials)"
TOK="$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)"
if [ -n "$TOK" ]; then
  md() { curl -s -m 2 -f -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null; }
  for k in instance-id instance-type ami-id placement/availability-zone instance-life-cycle; do echo "$k: $(md "$k")"; done
  echo "iam role: $(md iam/info | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("InstanceProfileArn","-"))' 2>/dev/null || echo none)"
  echo "IMDSv1 without a token: HTTP $(curl -s -o /dev/null -w '%{http_code}' -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null) (401 = IMDSv2 required)"
  echo "block devices: $(md block-device-mapping/ | tr '\n' ' ')"
  echo "network interfaces: $(md network/interfaces/macs/ | grep -c .)"
  if tags="$(md tags/instance/)"; then
    echo "tags:"; for t in $tags; do echo "  $t=$(md "tags/instance/$t")"; done
  else echo "tags: not exposed to the instance"; fi
else
  echo "no instance metadata service (not EC2, or blocked)"
fi
hdr "ec2 tooling";                 rpm -q ec2-instance-connect ec2-utils amazon-ssm-agent amazon-ec2-net-utils awscli-2 2>&1

# ---------------------------------------------------------------------------
sec "accounts and sudo"
hdr "login-capable accounts";      getent passwd | awk -F: '($3>=1000 || $3==0) {print $1, $3, $6, $7}'
hdr "password status";             for u in $(getent passwd | awk -F: '($3>=1000 || $3==0) && $7 !~ /nologin|false/ {print $1}'); do passwd -S "$u" 2>&1; done
hdr "privileged groups";           getent group wheel adm docker microk8s systemd-journal
hdr "/etc/sudoers (no comments)";  nocomment /etc/sudoers
hdr "/etc/sudoers.d";              ls -la /etc/sudoers.d/
for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "== $f"; nocomment "$f"; }; done
hdr "last logins";                 if have lastlog2; then lastlog2 | head -20; else lastlog 2>/dev/null | grep -v 'Never logged in' | head -20; fi
hdr "login history";               last -F -w 2>&1 | head -40
hdr "authorized_keys (fingerprints + option prefixes, never key material)"
# Read as the account whose home it is (from passwd: a folder's owner isn't its account, a chroot
# home is root's), so a link planted there can't make root print what it points to. A home with
# no account or several is skipped; root's own keys only when nobody else can change them.
for h in /root /home/*; do
  [ -d "$h" ] || continue
  if [ "$h" = /root ]; then acct=root
  else
    mapfile -t accts < <(getent passwd | awk -F: -v h="$h" '($6 == h || $6 == h "/") && $3 != 0 {print $1}')
    acct="${accts[0]:-}"; [ ${#accts[@]} -eq 1 ] || acct=""
  fi
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ -z "$acct" ]; then echo "== $f: skipped (the home of ${#accts[@]} accounts, not one)"; continue; fi
    if [ "$acct" = root ] && ! trusted "$f"; then echo "== $f: skipped (someone other than root can change it)"; continue; fi
    echo "== $f (read as $acct)"; ls -la "$f"
    runuser -u "$acct" -- ssh-keygen -lf "$f" 2>&1
    runuser -u "$acct" -- awk '$1 !~ /^(ssh-|ecdsa-|sk-)/ && NF {split($0,a," ssh-"); print "  options: " a[1]}' "$f"
  done
done
hdr "home sizes";                  $SLOW du -sh /root /home/* 2>/dev/null
hdr "other homes: file count + newest change (no names)"
for h in /home/*; do
  [ -n "$U" ] && [ "$h" = "$UHOME" ] && continue
  printf '%s files=%s newest=%s\n' "$h" "$($SLOW find "$h" -xdev 2>/dev/null | wc -l)" "$($SLOW find "$h" -xdev -printf '%T+\n' 2>/dev/null | sort | tail -1)"
done

# ---------------------------------------------------------------------------
sec "ssh"
hdr "sshd -T (effective config)";  sshd -T 2>&1 | sort
hdr "sshd unit: ExecStart and drop-ins (EC2 Instance Connect may hook in here)"
systemctl cat sshd 2>&1 | grep -E '^(# /|ExecStart|Environment)'
hdr "/etc/ssh listing";            ls -la /etc/ssh/ /etc/ssh/sshd_config.d/
hdr "sshd_config + drop-ins (no comments)"
nocomment /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && { echo "== $f"; nocomment "$f"; }; done
hdr "/etc/pam.d/sshd";             cat /etc/pam.d/sshd
hdr "authselect";                  if have authselect; then authselect current 2>&1; else echo "authselect not installed"; fi
hdr "sshd last 7 days: accepted logins (method user source)"
journalctl -u sshd --since '-7 days' --no-pager -o cat 2>/dev/null | sed -nE 's/^Accepted (\S+) for (\S+) from (\S+).*/\1 \2 \3/p' | sort | uniq -c | sort -rn | head -20
hdr "sshd last 7 days: noise counts"
journalctl -u sshd --since '-7 days' --no-pager -o cat 2>/dev/null | awk '
  /Invalid user/ {inv++} /Failed / {fail++} /penalty/ {pen++} /Connection closed by authenticating/ {pre++}
  END {printf "invalid_user=%d failed=%d penalty_msgs=%d preauth_closed=%d\n", inv, fail, pen, pre}'

# ---------------------------------------------------------------------------
sec "firewall"
if have firewall-cmd && active firewalld; then
  hdr "firewalld state";           firewall-cmd --state; firewall-cmd --get-default-zone; firewall-cmd --get-active-zones
  hdr "firewalld.conf";            nocomment /etc/firewalld/firewalld.conf
  hdr "active zones, runtime"
  for z in $(firewall-cmd --get-active-zones | grep -v '^ '); do firewall-cmd --zone="$z" --list-all; done
  hdr "active zones, permanent"
  for z in $(firewall-cmd --get-active-zones | grep -v '^ '); do firewall-cmd --permanent --zone="$z" --list-all; done
  hdr "policies";                  firewall-cmd --list-all-policies
  hdr "direct rules";              firewall-cmd --direct --get-all-rules
  firewall-cmd --list-all-zones > "$OUT/firewalld-all-zones.txt" 2>&1
else
  hdr "firewalld";                 echo "not running ($(rpm -q firewalld 2>&1))"
fi
hdr "nftables tables";             have nft && nft list tables || echo "nft not installed"
have nft && { printf 'full ruleset: '; tofile nft-ruleset.txt nft list ruleset; }
hdr "iptables backend + rule counts"
if have iptables; then
  iptables -V
  # only the nf_tables backend: the legacy tools can load kernel modules just by listing
  if iptables -V | grep -q nf_tables; then
    printf 'iptables-save:  '; tofile iptables-save.txt iptables-save
    printf 'ip6tables-save: '; tofile ip6tables-save.txt ip6tables-save
    echo "chains by owner: $(grep -oE '^:(KUBE|CILIUM|cali|FLANNEL|DOCKER|AWS)[A-Za-z_-]*' "$OUT/iptables-save.txt" | sed -E 's/^:(KUBE|CILIUM|cali|FLANNEL|DOCKER|AWS).*/\1/' | sort | uniq -c | tr '\n' ' ')"
  else
    echo "legacy backend: not listed here (see the nft ruleset)"
  fi
else
  echo "iptables not installed"
fi

# ---------------------------------------------------------------------------
sec "network"
hdr "addresses / routes";          ip -br addr; ip route; ip -6 route | head -20
hdr "listening sockets with processes"; ss -tulpnH
hdr "network manager";             for s in systemd-networkd NetworkManager; do echo "$s: $(systemctl is-active "$s" 2>&1)"; done
have networkctl && networkctl list --no-pager 2>&1
have nmcli && active NetworkManager && nmcli -t -f NAME,TYPE,DEVICE con show 2>&1
hdr "resolver";                    resolvectl status --no-pager 2>&1 | head -30; ls -l /etc/resolv.conf; nocomment /etc/resolv.conf
nocomment /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null
hdr "sysctl hardening-relevant"
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.default.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
  net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra \
  kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope \
  kernel.kexec_load_disabled fs.protected_symlinks fs.protected_hardlinks fs.suid_dumpable \
  net.core.bpf_jit_harden kernel.sysrq user.max_user_namespaces net.bridge.bridge-nf-call-iptables 2>&1
hdr "sysctl files";                ls /etc/sysctl.d/ /usr/lib/sysctl.d/ 2>&1; for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do [ -f "$f" ] && { echo "== $f"; nocomment "$f"; }; done
hdr "wireguard module";            modinfo -F filename wireguard 2>&1
hdr "time sync";                   timedatectl 2>&1 | head -8; chronyc sources 2>&1 | head -12

# ---------------------------------------------------------------------------
sec "kubernetes"
hdr "distributions and services"
for s in snap.microk8s.daemon-kubelite k3s k3s-agent rke2-server rke2-agent kubelet containerd docker crio; do
  systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . && echo "$s: $(systemctl is-active "$s" 2>&1)"
done
for f in /snap/bin/microk8s /usr/local/bin/k3s /var/lib/rancher/rke2/bin/kubectl /etc/kubernetes/admin.conf /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml; do
  [ -e "$f" ] && echo "present: $f"
done
hdr "which cluster, read as whom"
KCTL=() PINNED="${KCONTEXT}${KCONFIG}" TRIED=""
kube_bin() {   # kubectl as root: sudo's PATH leaves out /usr/local/bin
  local p
  for p in kubectl /usr/local/bin/kubectl /var/lib/rancher/rke2/bin/kubectl /snap/bin/kubectl; do
    have "$p" && { command -v "$p"; return; }
  done
}
# as the invoking user, through a login shell: their PATH, HOME and cloud credentials
AS_USER=(runuser -u "$U" -- bash -lc 'exec "$@"' -)
as_user() { "${AS_USER[@]}" "$@"; }
pick() {       # pick LABEL COMMAND... — read the cluster this way, if it answers
  local label="$1"; shift
  local ctx=(); [ -n "$KCONTEXT" ] && ctx=(--context "$KCONTEXT")
  # with --context, only a source whose kubeconfig has that context counts (config reads run nothing)
  if [ -n "$KCONTEXT" ] && ! "$@" config get-contexts -o name 2>/dev/null | grep -qxF -- "$KCONTEXT"; then return 1; fi
  TRIED=1
  echo "== $label"; "$@" config get-contexts 2>&1 | head -40
  if "$@" "${ctx[@]}" --request-timeout=20s get --raw /version >/dev/null 2>&1; then KCTL=("$@" "${ctx[@]}"); return 0; fi
  echo "   no answer"; return 1
}
stop() { [ -n "$TRIED" ] && [ -n "$PINNED" ]; }   # the named cluster was found and didn't answer
choose() {
  if [ -n "$KCONFIG" ]; then       # named on the command line: the invoking user's file, read as them
    if [ -n "$U" ]; then pick "$U's kubectl --kubeconfig $KCONFIG" "${AS_USER[@]}" kubectl --kubeconfig "$KCONFIG"
    elif ! trusted "$KCONFIG"; then echo "== $KCONFIG: not used (someone other than root can change it)"; TRIED=1; return 1
    else [ -n "$KB" ] && pick "kubectl --kubeconfig $KCONFIG" "$KB" --kubeconfig "$KCONFIG"; fi
    return
  fi
  if [ -n "$U" ] && as_user kubectl version --client >/dev/null 2>&1; then
    pick "$U's kubectl" "${AS_USER[@]}" kubectl && return 0; stop && return 1
  fi
  if [ -x /snap/bin/microk8s ]; then
    pick "microk8s (as root)" /snap/bin/microk8s kubectl && return 0; stop && return 1
  fi
  [ -n "$KB" ] || return 1
  local f
  for f in /etc/rancher/rke2/rke2.yaml /etc/rancher/k3s/k3s.yaml /etc/kubernetes/admin.conf /root/.kube/config; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    trusted "$f" || { echo "== $f: not used (someone other than root can change it)"; continue; }
    pick "$f (as root)" "$KB" --kubeconfig "$f" && return 0; stop && return 1
  done
  return 1
}
KB="$(kube_bin)"
if [ -n "$NOK8S" ]; then
  echo "skipped (--no-k8s)"
elif ! choose; then
  if [ -z "$PINNED" ]; then echo "no kubeconfig answered (pass --context/--kubeconfig, or this box has no cluster access)"
  elif [ -n "$TRIED" ]; then echo "the cluster named by --context/--kubeconfig didn't answer; nothing else was tried"
  else echo "no source has context $KCONTEXT; nothing else was tried"; fi
fi
if [ ${#KCTL[@]} -gt 0 ]; then
  k() { $T "${KCTL[@]}" --request-timeout=60s "$@"; }
  hdr "reading the cluster via";   printf '%q ' "${KCTL[@]}"; echo; k config current-context 2>&1
  hdr "versions";                  k version 2>&1
  hdr "nodes";                     printf 'nodes: '; tofile k8s-nodes.txt k get nodes -o wide; head -15 "$OUT/k8s-nodes.txt"
  hdr "namespaces";                k get ns --no-headers 2>&1 | awk '{print $1}' | tr '\n' ' '; echo
  hdr "pods";                      printf 'pods: '; tofile k8s-pods.txt k get pods -A -o wide
  echo "by namespace and status:"; awk 'NR>1 {print $1, $4}' "$OUT/k8s-pods.txt" | sort | uniq -c | sort -rn | head -40
  hdr "pods on the host network or with host ports (they listen on the nodes)"
  k get pods -A -o json 2>/dev/null | python3 -I -c '
import json, sys
for p in json.load(sys.stdin).get("items", []):
    s, m = p.get("spec", {}), p["metadata"]
    ports = sorted({pt["hostPort"] for ct in s.get("containers", []) for pt in ct.get("ports") or [] if pt.get("hostPort")})
    if s.get("hostNetwork") or ports:
        print(m["namespace"] + "/" + m["name"], "node=" + str(s.get("nodeName")), "hostNetwork" if s.get("hostNetwork") else "", "hostPorts=" + ",".join(map(str, ports)) if ports else "")
' | head -60
  hdr "services";                  printf 'services: '; tofile k8s-services.txt k get svc -A -o wide
  echo "by type:"; awk 'NR>1 {print $3}' "$OUT/k8s-services.txt" | sort | uniq -c
  hdr "ingress classes";           k get ingressclass 2>&1
  hdr "ingresses";                 printf 'ingresses: '; tofile k8s-ingress.txt k get ingress -A
  k get ingress -A -o json 2>/dev/null | python3 -I -c '
import collections, json, sys
items = json.load(sys.stdin).get("items", [])
cls, ann, domains = collections.Counter(), collections.Counter(), collections.Counter()
hosts, tls = set(), 0
for i in items:
    s, m = i.get("spec", {}), i["metadata"]
    a = m.get("annotations") or {}
    cls[s.get("ingressClassName") or a.get("kubernetes.io/ingress.class") or "(none)"] += 1
    hosts |= {r["host"] for r in s.get("rules") or [] if r.get("host")}
    tls += bool(s.get("tls"))
    for key in a:
        if "/" in key and not key.startswith(("kubectl.kubernetes.io/", "meta.helm.sh/")):
            ann[key] += 1
for h in hosts:
    domains[".".join(h.split(".")[-2:])] += 1
print(f"{len(items)} ingresses, {len(hosts)} distinct hosts, {tls} with tls")
print("by class:", dict(cls))
print("hosts by domain:", dict(domains.most_common(30)))
print("annotations in use (count):")
for key, n in ann.most_common(60):
    print(f"  {n:4} {key}")
'
  hdr "custom resource definitions"; printf 'crds: '; tofile k8s-crds.txt k get crd -o name
  grep -oE '[a-z0-9.-]+$' "$OUT/k8s-crds.txt" | sed -E 's/^[^.]+\.//' | sort | uniq -c | sort -rn | head -30
  crd() { grep -q "/$1\$" "$OUT/k8s-crds.txt"; }
  if crd gateways.gateway.networking.k8s.io; then
    hdr "gateway API";             k get gatewayclasses,gateways -A 2>&1 | head -40
    printf 'httproutes: '; tofile k8s-httproutes.txt k get httproutes -A
  fi
  if crd ingressroutes.traefik.io || crd ingressroutes.traefik.containo.us; then
    hdr "traefik";                 printf 'ingressroutes, middlewares, tls options: '; tofile k8s-traefik.txt k get ingressroutes,middlewares,tlsoptions -A
    echo "tls options with client auth (mTLS):"; k get tlsoptions -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.spec.clientAuth.clientAuthType}{"\n"}{end}' 2>&1
  fi
  if crd certificates.cert-manager.io; then
    hdr "cert-manager";            k get clusterissuers,issuers -A -o wide 2>&1 | head -40
    printf 'certificates: '; tofile k8s-certificates.txt k get certificates -A
    echo "not ready: $(awk 'NR>1 && $3!="True"' "$OUT/k8s-certificates.txt" | wc -l)"
  fi
  hdr "storage";                   k get storageclass 2>&1; printf 'pv/pvc: '; tofile k8s-volumes.txt k get pv,pvc -A
  hdr "cronjobs";                  k get cronjobs -A 2>&1 | head -40
  hdr "secrets and helm releases";  echo "not read (see the header)"
fi
if [ -x /snap/bin/microk8s ]; then
  hdr "microk8s args";             ls /var/snap/microk8s/current/args/
  hdr "snap refresh settings";     snap get system refresh 2>&1; snap refresh --time 2>&1; snap list --all
fi

# ---------------------------------------------------------------------------
sec "host proxies, CA and certificates (metadata only, never key contents)"
hdr "proxy services (active?)"
for s in nginx haproxy traefik envoy caddy httpd step-ca vault cfssl; do
  systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . && echo "$s: $(systemctl is-active "$s" 2>&1)"
done
hdr "CA tools";                    for b in step step-ca cfssl vault openssl easyrsa; do have "$b" && echo "$b: $(command -v "$b")"; done
for d in /etc/nginx /etc/haproxy /etc/traefik /etc/envoy /etc/caddy /etc/httpd; do
  [ -d "$d" ] || continue
  hdr "$d: files, names served and client-certificate settings"
  find "$d" -type f | head -60
  grep -rhoE '^\s*(server_name|ssl_verify_client|ssl_client_certificate|ssl_trusted_certificate)\s[^;]*' "$d" 2>/dev/null | sed -E 's/^\s+//' | sort | uniq -c | sort -rn | head -40
  grep -rhoE '\b(verify (required|optional)|ca-file \S+|crt \S+)' "$d" 2>/dev/null | sort | uniq -c | head -20
done
hdr "certificates on disk: path | subject | issuer | expires | CA?   (out/certs.txt)"
# kubelet pods, container layers and the system trust bundle are left out; local trust anchors are in
$SLOW find /etc /opt /srv /usr/local /var/lib /root ${UHOME:+"$UHOME"} -xdev \
  \( -path /var/lib/containerd -o -path /var/lib/docker -o -path /var/lib/kubelet/pods -o -path '/var/lib/rancher/*/agent/containerd' \
     -o -path /etc/pki/ca-trust/extracted -o -path /etc/pki/tls/certs -o -path /var/lib/snapd -o -path '*/node_modules' -o -path '*/.git' \) -prune \
  -o -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.cer' -o -name '*.cert' \) -size -128k -print 2>/dev/null |
while read -r f; do
  s="$(timeout 5 openssl x509 -in "$f" -noout -subject -issuer -enddate -ext basicConstraints 2>/dev/null | tr '\n' ' ')"
  [ -n "$s" ] || continue   # not a certificate (a key, a CSR, a bundle of something else)
  printf '%s | %s | certs=%s\n' "$f" "$s" "$(timeout 5 grep -c 'BEGIN CERTIFICATE' "$f")"
done > "$OUT/certs.txt"
echo "$(wc -l < "$OUT/certs.txt") certificate files"
echo "CA certificates:"; grep -c 'CA:TRUE' "$OUT/certs.txt"
echo "expired or expiring within 30 days:"
while IFS='|' read -r f rest; do
  e="$(sed -nE 's/.*notAfter=([^=]+GMT).*/\1/p' <<< "$rest")"; [ -n "$e" ] || continue
  [ "$(date -d "$e" +%s 2>/dev/null || echo 0)" -lt "$(( $(date +%s) + 30*86400 ))" ] && echo "  $f  ($e)"
done < "$OUT/certs.txt" | head -40
hdr "private key files (path, mode, owner only)"
$SLOW find /etc /opt /srv /usr/local /var/lib /root ${UHOME:+"$UHOME"} -xdev \
  \( -path /var/lib/containerd -o -path /var/lib/docker -o -path /var/lib/kubelet/pods -o -path /var/lib/snapd -o -path '*/node_modules' -o -path '*/.git' \) -prune \
  -o -type f \( -name '*.key' -o -name '*-key.pem' -o -name '*_key.pem' -o -name 'key.pem' \) -printf '%m %u:%g %p\n' 2>/dev/null | head -80

# ---------------------------------------------------------------------------
sec "containers"
if have docker && active docker; then
  hdr "docker info";               docker info --format 'server={{.ServerVersion}} driver={{.Driver}} cgroup={{.CgroupDriver}} root={{.DockerRootDir}}' 2>&1
  hdr "/etc/docker/daemon.json";   cat /etc/docker/daemon.json 2>&1
  hdr "containers";                docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}' | head -60
  hdr "space";                     $T docker system df 2>&1
else
  echo "docker: not running"
fi
have podman && { hdr "podman"; podman ps -a --format '{{.Names}} {{.Status}} {{.Image}}' 2>&1 | head -30; }
have crictl && { hdr "crictl"; echo "containers: $($T crictl ps -q 2>/dev/null | wc -l)"; }

# ---------------------------------------------------------------------------
sec "storage"
hdr "block devices";               lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL 2>&1 || lsblk
hdr "filesystems";                 df -hT -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs
hdr "fstab";                       nocomment /etc/fstab
hdr "nvme devices";                for d in /sys/class/nvme/nvme*; do [ -e "$d" ] && echo "$d $(cat "$d/model" 2>/dev/null) fw=$(cat "$d/firmware_rev" 2>/dev/null)"; done
case "$(stat -f -c %T /)" in
  btrfs)
    hdr "btrfs usage";             btrfs filesystem usage -T / 2>&1 | head -30
    hdr "btrfs subvolumes";        btrfs subvolume list / 2>&1 | head -60
    hdr "btrfs device stats";      btrfs device stats / 2>&1 ;;
  xfs)
    hdr "xfs_info /";              xfs_info / 2>&1 ;;
esac
have lvs && { hdr "lvm"; pvs 2>&1; vgs 2>&1; lvs 2>&1; }
grep -q '^md' /proc/mdstat 2>/dev/null && { hdr "/proc/mdstat"; cat /proc/mdstat; }
hdr "/var top level";              $SLOW du -xsh /var/* 2>/dev/null | sort -rh | head -15
hdr "/var/lib top";                $SLOW du -xsh /var/lib/* 2>/dev/null | sort -rh | head -15
hdr "/var/log top";                $SLOW du -xsh /var/log/* 2>/dev/null | sort -rh | head -10
hdr "/srv /opt /usr/local";        ls /srv /opt /usr/local/bin /usr/local/sbin 2>&1; $SLOW du -sh /srv /opt /usr/local 2>/dev/null
hdr "journald";                    journalctl --disk-usage; ls -d /var/log/journal 2>&1; nocomment /etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null
hdr "rsyslog";                     echo "rsyslog: $(systemctl is-active rsyslog 2>&1)"
hdr "coredumps";                   du -sh /var/lib/systemd/coredump 2>/dev/null; coredumpctl list --no-pager 2>/dev/null | tail -5
hdr "/boot";                       df -h /boot /boot/efi 2>/dev/null; ls /boot | grep -E '^vmlinuz'
hdr "network mounts (df only: du on a share can take ages)"
findmnt -t nfs,nfs4,cifs,smb3,efs; $T df -h -t nfs -t nfs4 -t cifs -t smb3 2>/dev/null
hdr "kernel warnings this boot (disk/RAID/NVMe health signals)"
journalctl -k -p warning -b --no-pager -o short 2>/dev/null | grep -iE 'nvme|md[0-9]|raid|btrfs|i/o error|ata|ext4|xfs|mce|hardware error' | tail -30

# ---------------------------------------------------------------------------
sec "packages and updates (from the dnf cache: nothing is downloaded)"
hdr "dnf";                         dnf --version 2>&1 | head -1; rpm -q system-release 2>&1
hdr "release lock";                for f in /etc/dnf/vars/*; do [ -f "$f" ] && echo "$f = $(cat "$f")"; done
hdr "newer releases (AL2023: asks the repo, installs nothing)"; cr="$(timeout 90 dnf check-release-update 2>&1)"; rc=$?; tail -15 <<< "$cr"; echo "exit $rc (0 and no text: no newer release)"
hdr "enabled repos";               dnf -C repolist --enabled 2>&1
hdr "version locks";               dnf -C versionlock list 2>&1 | head -30
hdr "package counts"
echo "installed: $(rpm -qa | wc -l)"
dnf -C repoquery --userinstalled --qf '%{name}\n' 2>&1 | grep . > "$OUT/userinstalled.txt"; echo "user-installed: $(wc -l < "$OUT/userinstalled.txt") (out/userinstalled.txt)"
hdr "most recent package installs"; rpm -qa --last | head -15
hdr "pending updates (from cache)"; dnf -C check-upgrade 2>&1 | grep -vE '^(Updating|Repositories loaded|Last metadata|$)' | wc -l
hdr "needs-restarting";            nr="$(dnf -C needs-restarting -r 2>&1)"; rc=$?; tail -5 <<< "$nr"; echo "exit $rc"
hdr "packages hb would use: in the repos (cache)?"
dnf -C list --available restic samba wireguard-tools smartmontools qrencode dnf-automatic cronie python3.11 python3.12 python3.13 python3.14 firewalld 2>&1 | grep -vE '^(Updating|Repositories|Last metadata)'
hdr "already installed?"
rpm -q restic samba wireguard-tools smartmontools qrencode dnf-automatic cronie python3.11 python3.12 python3.13 python3.14 firewalld btrfs-progs dnf-utils kpatch-runtime 2>&1
hdr "/etc/dnf/dnf.conf";           nocomment /etc/dnf/dnf.conf

# ---------------------------------------------------------------------------
sec "scheduled jobs"
hdr "/etc/crontab";                [ -f /etc/crontab ] && nocomment /etc/crontab || echo "no /etc/crontab"
hdr "cron dirs";                   ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>&1
hdr "user crontabs";               ls -la /var/spool/cron/ 2>&1
for f in /var/spool/cron/*; do [ -f "$f" ] && { echo "== $f"; nocomment "$f"; }; done
hdr "timers";                      systemctl list-timers --all --no-pager
hdr "custom units in /etc/systemd/system"; ls -la /etc/systemd/system/ | grep -vE '\.wants$|\.requires$|^total'
hdr "unit drop-ins in /etc/systemd/system"; ls -d /etc/systemd/system/*.d 2>/dev/null

# ---------------------------------------------------------------------------
# Hand the report over: the invoking user copies it into ./out/ with their own rights. Run as
# root without sudo, root writes there itself only if nobody else can change that folder;
# otherwise the report stays in root's folder. Root only reads its own folder, which then goes.
DEST="$HERE/out"
set -o pipefail
{
  if [ -n "$U" ]; then
    tar -C "$OUT" -cf - . | runuser -u "$U" -- sh -c 'umask 077 && mkdir -p "$1" && tar -C "$1" -xf -' sh "$DEST"
  elif trusted "$HERE" dir && { [ ! -e "$DEST" ] && [ ! -L "$DEST" ] || trusted "$DEST" dir; }; then
    mkdir -p "$DEST" && tar -C "$OUT" -cf - . | tar -C "$DEST" -xf -
  else
    echo "$HERE is a folder someone other than root can change: not writing there" >&3; false
  fi
} 2>&3
rc=$?
if [ "$rc" -eq 0 ]; then
  printf 'done: %s (%s lines)\n' "$DEST/inventory.txt" "$(wc -l < "$MAIN")" >&3
else
  trap - EXIT
  printf 'copying into %s failed (exit %s); the report stays in %s (root'"'"'s)\n' "$DEST" "$rc" "$OUT" >&3
  exit 1
fi
