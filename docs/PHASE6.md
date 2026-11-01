# Phase 6: upkeep

Phase 6 keeps the box current without you: upgrades every night, a reboot only
when one is needed and nobody is working, a morning digest, and the cleanup
and backup jobs moving from trial to routine. Keep a filled-in copy of this
runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Snap holds | `hb upgrade apply` | `snap refresh --hold` for `upgrade.snaps` (no more refreshes at random hours) |
| Nightly upgrade | `hb-upgrade.timer` (04:30, retried every 30 minutes until `upgrade.window_end`) | dnf upgrades; snaps refresh; a reboot when needed and idle; a read-only snapshot of `/` first |
| Morning digest | `hb-digest.timer` (06:45) | `/var/lib/hb/digest/`; one line in the login banner |
| Idle checks | `busy.d/` | nothing; they only answer "busy?" |

**How a night goes.** At 04:30 `hb upgrade run` takes a read-only snapshot
of `/` (kept `upgrade.snapshot_days`), runs `dnf upgrade --refresh -y`, then
refreshes the held snaps and reboots, each only if the box is idle. A microk8s
refresh restarts Kubernetes, so it waits like a reboot. A reboot happens only
when `dnf needs-restarting -r` asks for one (or a newer kernel is installed).
While busy, the next run at 05:00, 05:30 ... tries again; after
`upgrade.window_end` it waits for the next night. Each step happens at most
once a night.

**Idle** means every `busy.d` check passes:

| Check | Busy when |
|---|---|
| `sessions` | someone typed in a terminal (SSH, console, a tmux pane) or the web shell within `busy.idle_minutes` |
| `tmux` | any tmux pane runs something other than a shell: an agent, an editor, a job |
| `builds` | a process in `busy.processes` runs (make, cargo, pytest, dnf, ...), or an image build |
| `load` | the 5-minute load average is at or above `busy.max_load` |
| `jobs` | hb's backup, its maintenance or the cleanup is running |
| `hold` | `hb upgrade hold 8h` is in effect |
| `asterisk-calls` | a call is up |

So leaving an editor or an agent open in tmux means no reboot that night. A
reboot that has waited 7 days shows in `hb check` and in capitals in the
digest. With `upgrade.force_after_days` set, it then happens even when busy.

**The digest** at 06:45 reads what's already collected (every check, last
night's upgrade, the event log) and writes a page to `/var/lib/hb/digest/` and
a line to the banner: `last night: upgrade: 12 packages, rebooted 04:41 (...);
backup ...; cleanup ...`. `digest.reminders` ("YYYY-MM-DD text") show there
from their date on, for dated chores like the ones below.

**Risk.** Low to moderate: unattended upgrades and reboots. The snapshot and
that night's backup let you go back; the idle checks keep a reboot away from
your work; `hb upgrade hold` keeps one away from a planned evening.

## 0. Before you start

In `hb.toml`: `upgrade.enabled = true`, `upgrade.snaps`, and `"hb-upgrade"`
and `"hb-digest"` in `install.timers`. Optionally `digest.reminders`.

## 1. Install

    sudo ./hb install apply       # code, config, the two new timers

## 2. Hold the snaps

    sudo hb upgrade plan
    sudo hb upgrade apply

## 3. A first upgrade, watched

    sudo hb upgrade status        # ends with what keeps the box busy right now
    sudo hb upgrade now           # snapshot, dnf upgrade, then asks about snaps and a reboot

Say no to the snap refresh and the reboot if now isn't a good moment: the
night run does them when the box is idle.

## 4. The first digest

    sudo hb digest run

The banner shows its "last night" line from then on.

## 5. Later, dated chores

- After a week of cleanup reports: read `sudo hb clean report`, set
  `clean.dry_run = false`, `sudo ./hb install apply`.
- After two clean weeks of restic: disable the old backup job and delete its
  archives when you're satisfied.
- Old snapshots: `sudo hb snapshot prune`.

Put them in `digest.reminders` with their dates.

## Living with it

- Planning an evening of work that mustn't be interrupted at 04:30?
  `sudo hb upgrade hold 1d` (`off` to lift it early).
- `sudo hb upgrade status` says what keeps the box busy right now.
- A failed `dnf upgrade` is a failing check: an SMS after two refreshes.
- Fedora release upgrades stay manual.

## Rolling back

    sudo systemctl disable --now hb-upgrade.timer hb-digest.timer
    sudo snap refresh --unhold <snaps>

Take them out of `install.timers` so `hb install` doesn't enable them again.
A bad upgrade: boot the previous kernel from the boot menu (IPMI console), or
copy files back from `/.hb-snapshots/upgrade-<date>/`.
