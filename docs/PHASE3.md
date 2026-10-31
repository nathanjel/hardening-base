# Phase 3: network

Phases 1 and 2 closed doors and built the safety net. Phase 3 adds the private
way in (WireGuard from your PCs), puts the firewall under `hb.toml`, and trims
what listens. Keep a filled-in copy of this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Kernel settings | `hb harden` (sysctl) | `/etc/sysctl.d/90-hb.conf`, values set live |
| LLMNR off | `hb harden` (llmnr) | `/etc/systemd/resolved.conf.d/90-hb.conf`; systemd-resolved restarts |
| No certificate reissue | `hb k8s` (certs) | microk8s lock file `no-cert-reissue` |
| Cluster agent on localhost | `hb k8s` (agent) | `--bind` in microk8s's `args/cluster-agent`; the agent restarts |
| WireGuard | `hb wg` | wireguard-tools; `/etc/hb/secrets/wg-<if>.key`; `/etc/wireguard/<if>.conf`; `wg-quick@<if>` |
| Firewall | `hb fw` | the zone files listed in `fw.zones`; firewalld reloads |
| Outside view | `hb probe` | nothing: it runs on another machine |

**Why the certificate lock comes first:** microk8s's apiserver-kicker watches the
host's addresses. When one appears (a WireGuard interface, a new docker bridge,
docker starting after microk8s at boot), it reissues the API server certificate
and then stops every container and restarts containerd, so every pod restarts.
The lock stops that. An expired certificate still gets renewed (with the same
restart), so `hb k8s` fails `health.cert_warn_days` before expiry and you renew
at a quiet moment: `sudo microk8s refresh-certs --cert server.crt`. If you want
kubectl over WireGuard, the PC's kubeconfig names the server as the certificate
already knows it (`tls-server-name: kubernetes`) instead of the new address.

**Lockout risk.** Nothing here touches SSH itself, and the firewall change undoes
itself unless you confirm it from a new session. Still: work inside tmux, keep a
second SSH session open, and know how to reach your provider's console.

## 0. Look from outside first

On a machine outside the server's network (any OS with python3):

    git clone https://github.com/<you>/hardening-base
    python3 hardening-base/tools/hb-probe scan HOST --expect 22,80,443

`sudo hb probe` on the server prints that line with your values. Keep the output
to compare with step 6.

## 1. Install the new code and config

    sudo ./hb install apply

Until the steps below are done, the banner shows them as pending.

## 2. microk8s: freeze the certificate, agent to localhost

    sudo hb k8s plan
    sudo hb k8s apply        # certs, agent, agent_live: no pod restarts

## 3. Kernel settings and LLMNR

    sudo hb harden plan
    sudo hb harden apply     # sysctl, llmnr

`kernel.yama.ptrace_scope = 1` means `gdb -p`, `strace -p` and `py-spy` on a
process you didn't start from that shell need sudo.

## 4. WireGuard, no peers yet

    sudo hb wg apply         # package, key, conf, up
    ip -br addr show wg0

## 5. Firewall

    sudo hb fw plan          # the exact list of changes, per zone
    sudo hb fw apply         # reloads firewalld and starts the revert timer

Then, without closing that session, open a NEW ssh session. If it logs in:

    sudo hb fw confirm

If it doesn't, do nothing: the old zones come back by themselves after
`fw.revert_minutes` (or run `sudo hb fw revert` in the session you still have).

## 6. The first PC

1. Install WireGuard from wireguard.com/install. In the app: Add Tunnel → Add
   empty tunnel. Give it a name; the app shows the tunnel's **public key**.
2. Add the PC to `wg.peers` in `hb.toml`: `"desk 10.77.0.2 <that public key>"`.
3. On the server:

        sudo ./hb install apply
        sudo hb wg apply          # conf: + peer desk (live, no restart)
        sudo hb wg peer desk      # the lines to paste

4. In the app, edit the tunnel: keep `[Interface]` and `PrivateKey`, paste the
   rest below them, save, activate.
5. From the PC: `ssh you@10.77.0.1`. On the server, `sudo hb wg status` shows the
   handshake.

Only traffic for the server goes through the tunnel; the PC's internet stays as
it was.

## 7. Look from outside again

Same command as step 0. The open TCP ports should be what `--expect` lists, and
no UDP probe should get an answer.

    sudo hb check

## Rolling back

- **Firewall, before confirm:** `sudo hb fw revert`. After confirm: copy the zone
  files from `/var/lib/hb/backup/<run>/etc/firewalld/zones/` back, delete zone
  files that weren't there before, then `sudo firewall-cmd --reload`.
- **WireGuard:** `sudo systemctl disable --now wg-quick@wg0`.
- **Kernel settings:** delete `/etc/sysctl.d/90-hb.conf`; the old values return at the next boot.
- **LLMNR:** delete `/etc/systemd/resolved.conf.d/90-hb.conf`, then `sudo systemctl restart systemd-resolved`.
- **Certificate lock:** delete `/var/snap/microk8s/current/var/lock/no-cert-reissue`
  (the next new address then restarts every pod again).
- **Cluster agent:** copy `args/cluster-agent` back from `/var/lib/hb/backup/<run>/`,
  then `sudo snap restart microk8s.daemon-cluster-agent`.
