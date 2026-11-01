# Phase 7: recovery

Phase 7 proves the backup can be read and gives a way back from losing the
box: `hb restore` gets files back and runs a regular drill, and `hb rebuild`
(part 2) sets up a fresh box from the newest snapshot. Keep a filled-in copy of
this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Getting files back | `hb restore get` | a new folder in `/var/tmp/hb-restore/` (over the live files only with `--to /` and a yes) |
| The drill | `hb-restore.timer` (15 January, April, July, October, 02:30) | nothing lasting: a temporary folder in `/var/tmp`, removed afterwards; the result in `/var/lib/hb/restore/` |
| State dump | `hb inventory` (run by `hb backup`) | `/var/lib/hb/state`, now with accounts, add-ons and every Kubernetes object you made |
| Rebuild | `hb rebuild` | on the running box: only `/var/lib/hb/rebuild/stage`; on a fresh box, everything it's missing |

**The drill.** It lists the newest snapshot, picks `restore.sample_files`
random files (each up to `restore.max_file_mb`) and a few from every
`restore.must_have` path, and restores them with restic's `--verify`. Every
file that hasn't changed since the backup (same size, same modification time
to the nanosecond) must then match the live file byte for byte. Files changed
since are counted, not compared. So it checks the whole chain: what was read
at 04:00, what restic stored, and what comes back.

A mismatch, a file that doesn't come back, or a `must_have` path missing from
the snapshot fails `hb check`, which sends an SMS. The banner and SMS carry
counts only, never file names; `sudo hb restore status` has the paths.

**Risk.** Low: the drill only reads the repository and writes a temporary
folder. `hb restore get` writes over live files only when you pass `--to /`
and answer yes.

## 0. Before you start

In `hb.toml`: `"hb-restore"` in `install.timers`. Optionally `[restore]`:
`must_have` lists what every snapshot must hold, such as your application's
data folders.

## 1. Install

    sudo ./hb install apply       # code, config, hb-restore.timer

## 2. The first drill

    sudo hb restore drill         # a few minutes: most of it is listing the snapshot
    sudo hb restore status

## 3. Getting something back, once, to know how

    sudo hb restore list                          # snapshots
    sudo hb restore ls /etc/hb                    # what the newest one holds there
    sudo hb restore get /etc/hb/hb.toml           # into /var/tmp/hb-restore/<now>/etc/hb/hb.toml
    sudo hb restore get /etc/hb --from 1a2b3c4d   # an older snapshot, by its ID

The restored files sit at their full paths under the folder it prints.
Compare, then copy back what you need. `--to /` writes over the live files
after a yes, for when you really want the old version everywhere.

## Part 2: the state dump and hb rebuild

`hb inventory` now writes the state dump (`hb backup` calls it before each
backup). In it are JSON that `hb rebuild` reads: every Kubernetes object in
every namespace, except what the cluster makes itself; the add-ons; people's
accounts. `hb rebuild` compares a box with a snapshot's dump and adds what's
missing. On the running box it should find nothing, which shows a rebuild
would have what it needs. The whole way back from a blank box is
[RUNBOOK-rebuild.md](RUNBOOK-rebuild.md).

### 4. Install, and a backup that carries the new dump

    sudo ./hb install apply
    sudo hb inventory run && sudo hb inventory show
    sudo hb backup run            # or wait for tonight's

### 5. Compare the box with the backup

    sudo hb rebuild plan          # stages the newest snapshot, then: nothing to add
    sudo hb rebuild status        # one line per item

A unit you disabled since the last backup shows up as "will enable"; that
goes away with the next backup. Never `apply` on the running box: it only
adds, but it would re-enable such units and recreate objects you deleted on
purpose.

### 6. A copy of the runbook off the box

Fill in `local/REBUILD-<host>.md` from RUNBOOK-rebuild.md and keep it on your
PC and with the break-glass kit.

## Rolling back

    sudo systemctl disable --now hb-restore.timer

and take it out of `install.timers`. `hb rebuild` and `hb inventory` change
nothing outside `/var/lib/hb`.
