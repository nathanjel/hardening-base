# Phase 1: close the open doors

The first changes after the read-only inventory (`phase0/inventory.sh`): small,
reversible fixes for the problems that matter most and need no new services.
Which accounts, files and namespaces get touched comes entirely from `hb.toml`.
Keep your own filled-in copy of this runbook in `local/`, which git ignores.

| Typical problem | Fix | Tool item |
|---|---|---|
| NodePorts (often the microk8s registry on 32000) reachable from the internet: kube-proxy rewrites the traffic before firewalld's zone rules see it | kube-proxy `--nodeport-addresses` limited to loopback | `hb k8s` nodeport, nodeport_live |
| Every pod carries a service-account token, and the API server authorises everything (microk8s without RBAC) | the default service account stops mounting tokens in namespaces whose pods never call the API | `hb k8s` tokens, tokens_live |
| The cloud image's default user with passwordless sudo, or other unused accounts | accounts deleted, homes kept as root-only tarballs | `hb harden` accounts |
| A cloud-init sudo rule, or a key in root's `authorized_keys` | files moved to `/var/lib/hb/backup/<run>/` | `hb harden` files |
| sshd allows root with a key | `PermitRootLogin no` | `hb harden` root_login |
| A kernel update waiting for a reboot | supervised reboot | by hand, step 5 |

Everything runs from the checkout with sudo. Every `apply` asks before each item,
and copies whatever it changes to `/var/lib/hb/backup/<run>/` first.

## 0. Look first (changes nothing)

    sudo ./hb config check
    sudo ./hb harden plan
    sudo ./hb k8s plan
    sudo ./hb health status

## 1. Safety snapshot

    sudo ./hb snapshot create phase1

This makes a read-only copy of `/`, kept for `snapshot.keep_days`. It needs `/` on btrfs. It keeps everything
deleted or rewritten after it on the same disk, so don't keep it longer than you need. A file comes back with
`sudo cp -a /.hb-snapshots/phase1-<stamp>/etc/whatever /etc/whatever`.

## 2. Host doors

    sudo ./hb harden apply

nopasswd is a report only. Afterwards, open a **new** SSH session before closing
the current one, to prove you can still get in.

## 3. Kubernetes

    sudo ./hb k8s apply

- nodeport_live restarts kubelite. The API is down for about a minute, while running pods keep serving.
- tokens_live recreates the pods in the listed namespaces, but only when every `busy.d` check says now is fine (for example, no call up in Asterisk). Deployments with a ReadWriteOnce volume that don't use `Recreate` get scaled to 0 and back, so two copies never share the volume.

## 4. Check from outside

From another machine, the registry (or any NodePort) must now time out:

    curl -m 5 http://<public-ip>:32000/v2/_catalog

On the box it must still answer, and the checks should pass:

    curl -s localhost:32000/v2/_catalog
    sudo ./hb check

## 5. Reboot

1. Confirm nothing is busy: `for s in busy.d/*; do HB_ROOT=$PWD "$s" || echo "^ $s"; done`
2. Save work in tmux sessions. They end with the reboot, and so does any AI agent session running on the box.
3. `sudo systemctl reboot`

If the box isn't back after 10 minutes, use your provider's remote console (IPMI, KVM or
serial) and log in with an account that has a password. A locked root can't log in there.

## 6. After the reboot

    sudo ./hb health status        # Kubernetes may need 2–3 minutes after boot
    sudo ./hb check

Then run your applications' own smoke tests.

## 7. Later

    sudo ./hb snapshot prune

## Rolling back one item

- **NodePorts:** delete the `--nodeport-addresses` line in `/var/snap/microk8s/current/args/kube-proxy`, then `sudo snap restart microk8s.daemon-kubelite`.
- **Tokens:** `microk8s kubectl patch sa default -n <ns> -p '{"automountServiceAccountToken": null}'`, then restart that namespace's deployments.
- **Root login:** `sudo rm /etc/ssh/sshd_config.d/10-hb-harden.conf && sudo systemctl reload sshd`.
- **Removed files:** copies are in `/var/lib/hb/backup/<run>/` under their original paths.
- **Accounts:** homes are in `/var/lib/hb/backup/<run>/home-<user>.tar.gz`. Everything is also in the snapshot.
- **Kernel:** choose the previous kernel in the boot menu from the remote console.

cloud-init creates its default user only once per instance, so a deleted default
user doesn't come back at reboot. If it ever does, `hb harden check` reports it.
