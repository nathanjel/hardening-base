# hardening-base (`hb`)

An admin toolkit for one Linux server you work on remotely: many small tools
behind one `hb` command, bash and stdlib Python only, no third-party libraries
(one vendored data file: the EFF wordlist for passphrases, CC BY 3.0).
It targets Fedora/RHEL-family hosts (dnf, firewalld, btrfs), with an optional
microk8s plug-in. Nothing about a particular host lives in the repo: that goes
in `hb.toml` and `local/`, both git-ignored.

The goal is a box that is hardened, backed up and maintained by code you can
read in an afternoon. The planned pieces are WireGuard access, SSH with TOTP, a
small browser shell, a break-glass kit, encrypted restic backups, idle-aware
upgrades and cleanup jobs. They arrive in phases.

    hb <tool> <verb>     e.g. sudo ./hb k8s plan
    hb check             one line per tool

## Status

Phases 1 to 7 are written, phase 8 is next (runbooks:
[docs/PHASE1.md](docs/PHASE1.md), [docs/PHASE2.md](docs/PHASE2.md),
[docs/PHASE3.md](docs/PHASE3.md), [docs/PHASE4.md](docs/PHASE4.md),
[docs/PHASE5.md](docs/PHASE5.md), [docs/PHASE6.md](docs/PHASE6.md), [docs/PHASE7.md](docs/PHASE7.md)). Start from `hb.toml.example`, which lists every
key, as `hb.toml` in the checkout. `sudo ./hb install apply` then copies the code
to `/opt/hb` (root's, so nothing running as your user can change what root's
timers run) and the config to `/etc/hb/hb.toml`.

| Tool | Job |
|---|---|
| `hb-config` | read and validate `hb.toml` (bash tools call `hb config get KEY`) |
| `hb-install` | root-owned copy in `/opt/hb`, `/etc/hb/hb.toml`, systemd units and timers |
| `hb-harden` | unwanted accounts, stray files and folders, root login over SSH, NOPASSWD audit, kernel settings, LLMNR |
| `hb-k8s` | microk8s: NodePorts on localhost only, no service-account tokens in app pods, no certificate reissue that restarts every container, cluster agent on localhost |
| `hb-wg` | WireGuard endpoint for your PCs: config from `hb.toml`, each PC keeps its own private key |
| `hb-fw` | firewalld zones from `hb.toml`, applied with a revert timer you cancel from a new session |
| `hb-probe` | stdlib-only outside scan (TCP and a few UDP services) to run from another network |
| `hb-ssh` | who may log in and how: root-owned keys from `hb.toml`, one allowed group, key plus code from the internet and key only over WireGuard; applied with a revert timer |
| `hb-totp` | the code behind the key: RFC 6238 codes from an authenticator app and single-use recovery codes, checked by PAM through `pam_exec` |
| `hb-webshell` | your shell (tmux) in a browser: over WireGuard always, from the internet only for a window you open (`hb webshell open 2h`); own password and code, rate limits, stdlib daemon, pinned xterm.js |
| `hb-upgrade` | nightly dnf upgrade and held snap refresh, a pre-upgrade snapshot, a reboot only when needed and nobody is working (`busy.d`) |
| `hb-digest` | the morning summary: last night's upgrade, backup and cleanup, warnings, dated reminders; one line in the banner |
| `hb-share` | Windows drive letters over WireGuard: Samba on the tunnel interface only, SMB 3.1.1 with signing, one user |
| `hb-breakglass` | a rescue account and a printable kit for one trusted person: passphrase-protected key, recovery codes, console password, its own restic key; logging in to it sends an SMS |
| `hb-snapshot` | read-only btrfs snapshots of `/` before risky changes |
| `hb-health` | reboot pending, RAID, NVMe wear, btrfs, disk, mounts, containers, k8s, sites and certificates, registry, SIP trunk |
| `hb-status` | runs every check every 15 minutes, writes the login banner, passes changes to hb-notify |
| `hb-notify` | events for the banner; failures also as SMS through any command you name (rate-limited) |
| `hb-alerts` | mdadm and smartd report through hb-notify, no mail server needed |
| `hb-backup` | restic from a read-only btrfs snapshot, plus a state dump for rebuilding |
| `hb-restore` | files back from the backup (into a folder, or over the live ones after a yes), and a quarterly drill that restores a random sample and compares it byte for byte with the live files |
| `hb-clean` | build output in idle projects, stale caches, Docker leftovers; dry-run first. Measures the image registry, never cleans it |
| `hb-inventory` | the state dump a rebuild needs (packages, snaps, accounts, units, every Kubernetes object you made, ...), written before each backup |
| `hb-rebuild` | sets up a fresh box from the newest snapshot: files, packages, snaps, accounts, data, microk8s add-ons, Kubernetes objects, units; only ever adds. See [docs/RUNBOOK-rebuild.md](docs/RUNBOOK-rebuild.md) |
| `phase0/inventory.sh` | the read-only survey hb started from |

## Conventions

- Item tools (`harden`, `k8s`, `wg`, `install`, `alerts`, `breakglass`) share four verbs: `status`, `plan` (changes nothing),
  `apply [--yes]` (asks before each item) and `check` (one line; exit 0 ok, 1 pending, 2 broken).
  See `lib/hb.sh`.
- Anything changed is first copied to `/var/lib/hb/backup/<run>/`.
- Changes that could lock you out (`fw`, `ssh`) undo themselves after a few minutes unless
  confirmed from a new session (`lib/hbkit/guard.py`).
- `busy.d/` scripts say when now is a bad moment to disrupt things: a call in progress, recent typing
  in a terminal or the web shell, load, builds, a tmux pane running more than a shell, hb's own jobs,
  `hb upgrade hold`. Each prints why and exits 1 when busy; `hb upgrade` and `hb k8s` wait for all of them.
  Pod restarts consult them, and reboots will too.
- Python tools run as `python3 -IB`: isolated mode, no bytecode written.
- Defaults never change anything; only what `hb.toml` lists gets touched.
- `hooks/` holds what other programs call (mdadm, smartd); `units/` the systemd units.

Tests: `python3 -B -m unittest discover -s tests`

MIT licensed, see [LICENSE](LICENSE).
