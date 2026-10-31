#!/usr/bin/env bash
# Phase 0 inventory for hardening-base. READ-ONLY: it lists, shows and measures,
# and changes nothing on the system. Output lands in ./out/ next to this script,
# owned by the invoking user, mode 0700.
#
# Deliberately NOT collected: password hashes, private keys, k8s secret values,
# file names inside other users' homes, application/journal log content
# (only kernel warnings and sshd auth summaries).
#
# Usage:  sudo bash phase0/inventory.sh
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo bash $0" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"
MAIN="$OUT/inventory.txt"
: > "$MAIN"
K="/snap/bin/microk8s kubectl"
T="timeout 90"

exec 3>&1            # keep the terminal for progress
exec >>"$MAIN" 2>&1  # everything else goes to the report

sec() { printf '\n\n######## %s ########\n' "$*"; printf '  %s\n' "$*" >&3; }
hdr() { printf '\n$ %s\n' "$*"; }

# ---------------------------------------------------------------------------
sec "system"
hdr "date / uptime / kernel";      date; uptime; uname -a; cat /proc/cmdline
hdr "installed kernels";           rpm -q kernel-core; echo "running: $(uname -r)"
hdr "selinux";                     getenforce; grep -vE '^\s*(#|$)' /etc/selinux/config
hdr "secure boot";                 mokutil --sb-state 2>/dev/null || echo "mokutil not available"
hdr "cloud-init";                  cloud-init status 2>/dev/null || echo "cloud-init not available"
hdr "failed units";                systemctl --failed --no-pager
hdr "enabled unit files";          systemctl list-unit-files --state=enabled --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
hdr "running services";            systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
hdr "processes by user (command names only)"; ps -eo user:20,comm --no-headers | sort | uniq -c | sort -rn | head -60

# ---------------------------------------------------------------------------
sec "accounts and sudo"
hdr "login-capable accounts";      getent passwd | awk -F: '($3>=1000 || $3==0) {print $1, $3, $6, $7}'
hdr "password status";             for u in $(getent passwd | awk -F: '($3>=1000 || $3==0) && $7 !~ /nologin|false/ {print $1}'); do passwd -S "$u"; done
hdr "privileged groups";           getent group wheel docker microk8s adm systemd-journal
hdr "/etc/sudoers (no comments)";  grep -vE '^\s*(#|$)' /etc/sudoers
hdr "/etc/sudoers.d";              ls -la /etc/sudoers.d/
for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "== $f"; grep -vE '^\s*(#|$)' "$f"; }; done
hdr "last logins (lastlog2)";      lastlog2 2>/dev/null | head -20
hdr "login history";               last -F -w | head -40
hdr "authorized_keys (fingerprints + option prefixes, never key material)"
for h in /root /home/*; do
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
    [ -f "$f" ] || continue
    echo "== $f"; ls -la "$f"
    ssh-keygen -lf "$f" 2>&1
    awk '$1 !~ /^(ssh-|ecdsa-|sk-)/ && NF {split($0,a," ssh-"); print "  options: " a[1]}' "$f"
  done
done
hdr "home sizes";                  du -sh /root /home/* 2>/dev/null
hdr "other homes: file count + newest change (no names)"
for h in /home/*; do
  [ -n "${SUDO_USER:-}" ] && [ "$h" = "/home/$SUDO_USER" ] && continue
  printf '%s files=%s newest=%s\n' "$h" "$(find "$h" -xdev 2>/dev/null | wc -l)" "$(find "$h" -xdev -printf '%T+\n' 2>/dev/null | sort | tail -1)"
done

# ---------------------------------------------------------------------------
sec "ssh"
hdr "sshd -T (effective config)";  sshd -T 2>&1 | sort
hdr "/etc/ssh listing";            ls -la /etc/ssh/ /etc/ssh/sshd_config.d/
hdr "sshd_config + drop-ins (no comments)"
grep -vE '^\s*(#|$)' /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && { echo "== $f"; grep -vE '^\s*(#|$)' "$f"; }; done
hdr "/etc/pam.d/sshd";             cat /etc/pam.d/sshd
hdr "sshd last 7 days: accepted logins (method user source)"
journalctl -u sshd --since '-7 days' --no-pager -o cat 2>/dev/null | sed -nE 's/^Accepted (\S+) for (\S+) from (\S+).*/\1 \2 \3/p' | sort | uniq -c | sort -rn | head -20
hdr "sshd last 7 days: noise counts"
journalctl -u sshd --since '-7 days' --no-pager -o cat 2>/dev/null | awk '
  /Invalid user/ {inv++} /Failed / {fail++} /penalty/ {pen++} /Connection closed by authenticating/ {pre++}
  END {printf "invalid_user=%d failed=%d penalty_msgs=%d preauth_closed=%d\n", inv, fail, pen, pre}'

# ---------------------------------------------------------------------------
sec "firewall"
hdr "firewalld state";             firewall-cmd --state; firewall-cmd --get-default-zone; firewall-cmd --get-active-zones
hdr "firewalld.conf";              grep -vE '^\s*(#|$)' /etc/firewalld/firewalld.conf
hdr "active zones, runtime"
for z in $(firewall-cmd --get-active-zones | grep -v '^ '); do firewall-cmd --zone="$z" --list-all; done
hdr "active zones, permanent"
for z in $(firewall-cmd --get-active-zones | grep -v '^ '); do firewall-cmd --permanent --zone="$z" --list-all; done
hdr "policies";                    firewall-cmd --list-all-policies
hdr "direct rules";                firewall-cmd --direct --get-all-rules
hdr "custom zone/policy files";    ls -la /etc/firewalld/zones /etc/firewalld/policies 2>/dev/null
for f in /etc/firewalld/zones/*.xml /etc/firewalld/policies/*.xml; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done
firewall-cmd --list-all-zones > "$OUT/firewalld-all-zones.txt" 2>&1
hdr "nftables tables";             nft list tables
nft list ruleset > "$OUT/nft-ruleset.txt" 2>&1
echo "full ruleset: $(wc -l < "$OUT/nft-ruleset.txt") lines in out/nft-ruleset.txt"
hdr "firewalld INPUT / FORWARD chains"
nft list chain inet firewalld filter_INPUT 2>&1 | head -80
nft list chain inet firewalld filter_FORWARD 2>&1 | head -80
hdr "iptables backend + rule counts"
iptables -V
iptables-save  > "$OUT/iptables-save.txt"  2>&1; echo "iptables-save:  $(wc -l < "$OUT/iptables-save.txt") lines"
ip6tables-save > "$OUT/ip6tables-save.txt" 2>&1; echo "ip6tables-save: $(wc -l < "$OUT/ip6tables-save.txt") lines"
command -v iptables-legacy-save >/dev/null && echo "legacy: $(iptables-legacy-save 2>/dev/null | grep -c '^-A') rules"
hdr "NodePort handling in iptables"
grep -E 'KUBE-NODEPORTS|nodeport' "$OUT/iptables-save.txt" | head -30

# ---------------------------------------------------------------------------
sec "network"
hdr "addresses / routes";          ip -br addr; ip route; ip -6 route | head -20
hdr "listening sockets with processes"; ss -tulpnH
hdr "resolved";                    resolvectl status --no-pager 2>&1 | head -30
grep -rvE '^\s*(#|$)' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null
hdr "sysctl hardening-relevant"
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.default.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
  net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra \
  kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope \
  kernel.kexec_load_disabled fs.protected_symlinks fs.protected_hardlinks fs.suid_dumpable \
  net.core.bpf_jit_harden kernel.sysrq user.max_user_namespaces 2>&1
hdr "NetworkManager connections";  nmcli -t -f NAME,TYPE,DEVICE con show 2>&1
hdr "wireguard module";            modinfo -F filename wireguard 2>&1
hdr "time sync";                   chronyc sources 2>&1 | head -12

# ---------------------------------------------------------------------------
sec "microk8s"
hdr "args directory";              ls /var/snap/microk8s/current/args/
for a in kube-proxy kubelet kube-apiserver cluster-agent kube-controller-manager kube-scheduler; do
  f="/var/snap/microk8s/current/args/$a"; [ -f "$f" ] && { echo "== $a"; grep -vE '^\s*(#|$)' "$f"; }
done
hdr "snap refresh settings";       snap get system refresh 2>&1; snap refresh --time 2>&1; snap list --all
hdr "nodes";                       $T $K get nodes -o wide
hdr "pods";                        $T $K get pods -A -o wide
hdr "services";                    $T $K get svc -A -o wide
hdr "ingress";                     $T $K get ingress -A
hdr "pv / pvc";                    $T $K get pv,pvc -A
hdr "cronjobs";                    $T $K get cronjobs -A
hdr "secrets (names and types only)"; $T $K get secrets -A --no-headers | awk '{print $1, $2, $3}'
hdr "registry deployment env + volumes"
$T $K -n container-registry get deploy registry -o jsonpath='{.spec.template.spec.containers[0].env}{"\n"}{.spec.template.spec.volumes}{"\n"}'
hdr "registry service traffic policy"
$T $K -n container-registry get svc registry -o jsonpath='{.spec.type} externalTrafficPolicy={.spec.externalTrafficPolicy}{"\n"}'
hdr "ingress pods: hostNetwork + ports"
$T $K -n ingress get pods -o jsonpath='{range .items[*]}{.metadata.name}{" hostNetwork="}{.spec.hostNetwork}{" ports="}{.spec.containers[*].ports}{"\n"}{end}'
hdr "calico-node env (plain values only)"
$T $K -n kube-system get ds calico-node -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'
hdr "felix configuration"
$T $K get felixconfigurations.crd.projectcalico.org -o yaml 2>&1 | grep -vE 'creationTimestamp|resourceVersion|uid:|generation|managedFields' | head -50
hdr "k8s storage sizes"
du -sh /var/snap/microk8s/common/default-storage/* 2>/dev/null
du -sh /var/snap/microk8s/common/var/lib/containerd 2>/dev/null
echo "containerd k8s.io images: $(/snap/bin/microk8s ctr -n k8s.io images ls -q 2>/dev/null | wc -l)"

# ---------------------------------------------------------------------------
sec "docker"
hdr "docker info";                 docker info --format 'server={{.ServerVersion}} driver={{.Driver}} cgroup={{.CgroupDriver}} root={{.DockerRootDir}}' 2>&1
hdr "/etc/docker/daemon.json";     cat /etc/docker/daemon.json 2>&1
hdr "containers";                  docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}'
hdr "restart policies"
for c in $(docker ps -aq); do docker inspect -f '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}} net={{.HostConfig.NetworkMode}}' "$c"; done
hdr "volumes";                     docker system df -v 2>&1 | sed -n '/Local Volumes space usage/,/Build cache usage/p' | head -30
hdr "images (newest first)";       docker images --format '{{.CreatedAt}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}' | sort -r | head -70
hdr "docker/containerd dirs";      du -sh /var/lib/docker /var/lib/containerd 2>/dev/null

# ---------------------------------------------------------------------------
sec "storage"
hdr "btrfs usage";                 btrfs filesystem usage -T / 2>&1 | head -30
hdr "btrfs subvolumes";            btrfs subvolume list / 2>&1 | head -60
hdr "btrfs device stats";          btrfs device stats / 2>&1
hdr "btrfs scrub status";          btrfs scrub status / 2>&1
hdr "/proc/mdstat";                cat /proc/mdstat
hdr "md3 detail";                  mdadm --detail /dev/md3 2>&1 | grep -E 'State|Devices|Level|Events|/dev/'
hdr "mdadm.conf";                  grep -vE '^\s*(#|$)' /etc/mdadm.conf 2>&1
hdr "nvme devices";                for d in /sys/class/nvme/nvme*; do echo "$d $(cat "$d/model" 2>/dev/null) fw=$(cat "$d/firmware_rev" 2>/dev/null)"; done
hdr "/var top level";              du -xsh /var/* 2>/dev/null | sort -rh | head -15
hdr "/var/lib top";                du -xsh /var/lib/* 2>/dev/null | sort -rh | head -15
hdr "/var/log top";                du -xsh /var/log/* 2>/dev/null | sort -rh | head -10
hdr "/srv sizes";                  du -sh /srv/* /srv/*/* 2>/dev/null
hdr "/opt and /usr/local";         ls /opt /usr/local/bin /usr/local/sbin 2>&1; du -sh /opt /usr/local 2>/dev/null
hdr "journald";                    journalctl --disk-usage; grep -rvE '^\s*(#|$)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null
hdr "coredumps";                   du -sh /var/lib/systemd/coredump 2>/dev/null; coredumpctl list --no-pager 2>/dev/null | tail -5
hdr "/boot";                       df -h /boot /boot/efi; ls /boot | grep -E '^vmlinuz'
hdr "network mounts (df only: du on a share can take ages)"
findmnt -t nfs,nfs4,cifs,smb3; $T df -h -t nfs -t nfs4 -t cifs -t smb3 2>/dev/null
hdr "kernel warnings this boot (disk/RAID/NVMe health signals)"
journalctl -k -p warning -b --no-pager -o short 2>/dev/null | grep -iE 'nvme|md[0-9]|raid|btrfs|i/o error|ata|ext4|xfs|mce|hardware error' | tail -30

# ---------------------------------------------------------------------------
sec "packages and updates"
hdr "enabled repos";               dnf -C repo list --enabled 2>&1
hdr "package counts"
echo "installed: $(rpm -qa | wc -l)"
dnf -C repoquery --userinstalled --qf '%{name}\n' > "$OUT/userinstalled.txt" 2>&1; echo "user-installed: $(wc -l < "$OUT/userinstalled.txt") (out/userinstalled.txt)"
hdr "most recent package installs"; rpm -qa --last | head -15
hdr "pending updates (from cache)"; dnf -C check-upgrade 2>&1 | grep -vE '^(Updating|Repositories loaded|$)' | wc -l
hdr "needs-restarting";            dnf needs-restarting -r 2>&1 | tail -5
hdr "candidate packages in repos (cache)"
dnf -C list --available restic samba wireguard-tools smartmontools qrencode podman dnf5-plugin-automatic nvme-cli 2>&1 | grep -vE '^(Updating|Repositories)'
hdr "already installed?"
rpm -q restic samba wireguard-tools smartmontools qrencode podman dnf5-plugin-automatic nvme-cli 2>&1
hdr "/etc/dnf/dnf.conf";           grep -vE '^\s*(#|$)' /etc/dnf/dnf.conf

# ---------------------------------------------------------------------------
sec "scheduled jobs"
hdr "/etc/crontab";                grep -vE '^\s*(#|$)' /etc/crontab
hdr "cron dirs";                   ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>&1
hdr "user crontabs";               ls -la /var/spool/cron/ 2>&1
for f in /var/spool/cron/*; do [ -f "$f" ] && { echo "== $f"; grep -vE '^\s*(#|$)' "$f"; }; done
hdr "timers";                      systemctl list-timers --all --no-pager
hdr "custom units in /etc/systemd/system"; ls -la /etc/systemd/system/ | grep -vE '\.wants$|\.requires$|^total'

# ---------------------------------------------------------------------------
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT"
chmod 700 "$OUT"
printf 'done: %s (%s lines)\n' "$MAIN" "$(wc -l < "$MAIN")" >&3
