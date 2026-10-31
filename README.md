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

Phase 1 tools are written (runbook: [docs/PHASE1.md](docs/PHASE1.md)). They run from
the checkout with sudo and read `./hb.toml` (start from `hb.toml.example`, which
lists every key), or `/etc/hb/hb.toml` once installed.

| Tool | Job |
|---|---|
| `hb-config` | read and validate `hb.toml` (bash tools call `hb config get KEY`) |
| `hb-harden` | unwanted accounts, stray files, root login over SSH, NOPASSWD audit |
| `hb-k8s` | microk8s: NodePorts on localhost only, no service-account tokens in app pods |
| `hb-snapshot` | read-only btrfs snapshots of `/` before risky changes |
| `hb-health` | reboot pending, RAID, btrfs, disk, mounts, containers, k8s, sites, registry, SIP trunk |
| `phase0/inventory.sh` | read-only system inventory (becomes `hb-inventory`) |

## Conventions

- Item tools (`harden`, `k8s`) share four verbs: `status`, `plan` (changes nothing),
  `apply [--yes]` (asks before each item) and `check` (one line; exit 0 ok, 1 pending, 2 broken).
  See `lib/hb.sh`.
- Anything changed is first copied to `/var/lib/hb/backup/<run>/`.
- `busy.d/` scripts say when now is a bad moment to disrupt things (a call in progress).
  Pod restarts consult them, and reboots will too.
- Python tools run as `python3 -IB`: isolated mode, no bytecode written.
- Defaults never change anything; only what `hb.toml` lists gets touched.

Tests: `python3 -m unittest discover -s tests`

MIT licensed, see [LICENSE](LICENSE).
