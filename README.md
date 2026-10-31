# hardening-base (`hb`)

An admin toolkit for one Linux server you work on remotely: many small tools
behind one `hb` command, bash and stdlib Python only, no third-party libraries.
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

Phases 1 to 3 are written (runbooks: [docs/PHASE1.md](docs/PHASE1.md),
[docs/PHASE2.md](docs/PHASE2.md), [docs/PHASE3.md](docs/PHASE3.md)). Start from `hb.toml.example`, which lists every
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
| `hb-snapshot` | read-only btrfs snapshots of `/` before risky changes |
| `hb-health` | reboot pending, RAID, NVMe wear, btrfs, disk, mounts, containers, k8s, sites and certificates, registry, SIP trunk |
| `hb-status` | runs every check every 15 minutes, writes the login banner, passes changes to hb-notify |
| `hb-notify` | events for the banner; failures also as SMS through any command you name (rate-limited) |
| `hb-alerts` | mdadm and smartd report through hb-notify, no mail server needed |
| `hb-backup` | restic from a read-only btrfs snapshot, plus a state dump for rebuilding |
| `hb-clean` | build output in idle projects, stale caches, Docker leftovers; dry-run first |
| `phase0/inventory.sh` | read-only system inventory (becomes `hb-inventory`) |

## Conventions

- Item tools (`harden`, `k8s`, `wg`, `install`, `alerts`) share four verbs: `status`, `plan` (changes nothing),
  `apply [--yes]` (asks before each item) and `check` (one line; exit 0 ok, 1 pending, 2 broken).
  See `lib/hb.sh`.
- Anything changed is first copied to `/var/lib/hb/backup/<run>/`.
- `busy.d/` scripts say when now is a bad moment to disrupt things (a call in progress).
  Pod restarts consult them, and reboots will too.
- Python tools run as `python3 -IB`: isolated mode, no bytecode written.
- Defaults never change anything; only what `hb.toml` lists gets touched.
- `hooks/` holds what other programs call (mdadm, smartd); `units/` the systemd units.

Tests: `python3 -B -m unittest discover -s tests`

MIT licensed, see [LICENSE](LICENSE).
