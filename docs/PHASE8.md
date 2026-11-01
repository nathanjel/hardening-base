# Phase 8: knowing the box

Phase 8 adds two ways of seeing what the box is doing without having to look:
`hb disk` says where the space goes, and `hb inventory` now says what changed
on the box since the night before. Both only report. Keep a filled-in copy of
this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Disk scan | `hb disk`, `hb-disk.timer` (Sundays 03:15) | nothing but its result in `/var/lib/hb/disk/` |
| Drift | `hb inventory` (run by `hb backup`) | five more files in the state dump, and `/var/lib/hb/inventory/drift.jsonl` |
| Digest | `hb digest` | two more lines in the morning summary |

**The disk scan.** It walks every local filesystem once: not network shares,
snap images, containers' mounts, tmpfs or hb's snapshots. It counts each
hard-linked file once. `sudo hb disk` then shows:
- the filesystems now;
- the biggest folders (`disk.show_gb` and up), a folder that is nearly all one
  subfolder shown as one line;
- what grew since the scan before;
- folders of `disk.stale_gb` or more under `disk.stale_roots` where no file has
  changed for `disk.stale_days`.

"Untouched" goes by the newest file inside, not the folder's own date. So
hb clean deleting a project's build folder doesn't make the project look used.
`hb disk scan ~/somewhere` works without sudo, for anything you can read, and
keeps nothing.

**Drift.** Each `hb inventory run` (that is, each backup) compares the new
state dump with the one before. It covers the kernel and OS, packages,
repositories, snaps, accounts, groups, enabled units, listening sockets,
firewall zones, sudoers, SSH keys (fingerprints), cron, containers, microk8s
add-ons, Kubernetes objects and network addresses.

The dump gains five pieces for this: `groups.txt`, `sudoers.txt`,
`ssh-keys.txt`, `cron.txt` and `listening.txt`. Never in them: private keys,
password hashes or secret values. A Kubernetes object counts as changed only
when something you'd set changes, not its status or the server's bookkeeping.
Objects a controller makes are left out (a CronJob's Jobs, a Service's
EndpointSlices). A secret shows as changed without its values.

The morning digest lists the last 24 hours, and the banner says how many.
`sudo hb inventory drift 30` shows a month. Expected changes you'd rather not
see go in `inventory.drift_ignore` as regexes.

**Privacy.** The digest and the banner name no folders. Drift lines name
packages, accounts, ports and object names, never contents.

**Risk.** None to the running system: reading only. A scan takes a minute or
two at idle I/O priority.

## 0. Before you start

In `hb.toml`: `"hb-disk"` in `install.timers`. Optionally `[disk]`:
`stale_ignore` lists folders kept on purpose however old they are (an
application's recordings, a training corpus). `[inventory]`: `drift_ignore`.

## 1. Install

    sudo ./hb install apply       # code, config, hb-disk.timer

## 2. The first disk scan

    sudo hb disk scan             # a minute or two; then the report
    sudo hb disk                  # the same later, with the filesystems now

Look over the untouched folders. Add any you keep on purpose to
`disk.stale_ignore`, then `sudo ./hb install apply` again.

## 3. The first drift

The next `hb inventory run` compares against a dump without the five new
pieces. Those pieces are skipped that once, so they don't show up as
everything added.

    sudo hb inventory run         # 0 changes since the dump of ...
    sudo hb inventory drift

From the following night on, the digest has a `changes:` section when
something changed, and a `disk scan:` line after the first Sunday.

## 4. Check

    sudo hb check                 # disk: ok: scanned ...; inventory: ok

## Rolling back

    sudo systemctl disable --now hb-disk.timer    # and drop "hb-disk" from install.timers
    sudo rm -r /var/lib/hb/disk /var/lib/hb/inventory

The new dump pieces are harmless to leave. An older checkout ignores them.
