# Rebuilding the box from the backup

For when the box is gone or can't be trusted: a dead disk, a break-in, a
reinstall. About three hours of work plus the time to copy your data back.
Keep a filled-in copy (`local/REBUILD-<host>.md`) somewhere other than the
box: on your PC, and printed with the break-glass kit.

**You need:**
- the repository password (printed by `hb backup init`; the break-glass kit
  also carries its own restic key);
- a way for the new box to reach the backup storage;
- your SSH key;
- this runbook.

**What comes back** (everything below is in the backup):
- `/etc/hb`: hb's config and its secrets, i.e. the restic password, the
  WireGuard server key (your PCs reconnect unchanged), the TOTP secrets (the
  same authenticator entries work) and the web shell's login;
- the SSH host keys, so clients see the same fingerprints;
- packages, snaps, accounts with their passwords, enabled services;
- your data (`backup.paths`);
- the microk8s add-ons and every Kubernetes object you made, secrets and
  volumes included.

**What doesn't:**
- Docker images and volumes, and the image registry's contents: rebuild them
  from source;
- Samba's password database: `hb share password`;
- Kubernetes Jobs: not restarted on purpose.

## 0. A fresh box

Install the same distribution, Fedora 44 or newer, with a btrfs root (hb's
snapshots need it). Add your SSH key and set the old host name:

    sudo hostnamectl set-hostname <the old name>

With a new name, add `--host <old short name>` to every `hb rebuild`
command below.

## 1. Reach the backup

    sudo dnf install -y restic git nfs-utils
    sudo mkdir -p <backup.require_mount>
    sudo mount <the share> <backup.require_mount>

If the storage only accepts listed addresses, allow the new box's address
first.

## 2. Restore what everything else starts from

restic itself, by hand, with the password at its prompt:

    export RESTIC_REPOSITORY=<backup.repo>
    sudo -E restic snapshots --host <old short name> --tag hb --latest 3
    sudo -E restic restore latest --host <old short name> --tag hb --target / \
        --include /etc/hb --include '/etc/ssh/ssh_host_*' --include <your hardening-base checkout>
    sudo systemctl restart sshd      # the old host keys

From here on hb finds the password in `/etc/hb/secrets/restic-password`.

## 3. hb rebuild

Run it from the checkout. `hb install` comes later, once the account that owns
the checkout exists again.

    cd <your hardening-base checkout>
    sudo ./hb rebuild plan
    sudo ./hb rebuild apply

It goes through files, packages, snaps, users, data, addons, k8s and units,
asking before each. The data item restores your folders and takes hours.

Some items wait for an earlier one: snaps need snapd from packages, and groups
come with packages and snaps. So run `plan` again, and `apply` again, until it
says `nothing to add`. The Kubernetes objects come up with their images
missing; your applications' step below builds them.

## 4. hb itself

    sudo ./hb install apply          # /opt/hb, /etc/hb/hb.toml, units, timers

## 5. The doors, in this order

    sudo hb harden apply
    sudo hb k8s apply                # before WireGuard: no certificate reissue when wg0 appears
    sudo hb fw apply                 # then from a NEW session: sudo hb fw confirm
    sudo hb wg apply
    sudo hb ssh apply                # then from a NEW session: sudo hb ssh confirm
    sudo hb share apply && sudo hb share password
    sudo hb webshell apply
    sudo hb alerts apply
    sudo hb upgrade apply            # holds the snaps again
    sudo hb breakglass status        # the rescue account came back with users

## 6. Your applications

Images, containers and anything else outside hb: your `local/` copy lists
them.

## 7. Check

    sudo reboot
    sudo hb check
    sudo hb rebuild plan             # nothing to add
    sudo hb backup run               # the first backup from the new box
    sudo hb restore drill

From another network: `hb probe <address>`.

## 8. If the address changed

Update DNS, then everything that names the old address. Your `local/` copy
lists them.
