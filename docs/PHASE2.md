# Phase 2: the safety net

Phase 1 closed doors. Phase 2 makes sure you hear about trouble and can recover
from it: alerts that reach you without a mail server, encrypted backups you can
rebuild from, and cleanup that only reports at first. Nothing here touches
network access or logins. Keep a filled-in copy of this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| hb runs from a root-owned copy | `hb install` | `/opt/hb`, `/usr/local/bin/hb`, `/etc/hb/hb.toml`, units in `/etc/systemd/system`, the timers in `install.timers` |
| Disk and RAID alerts | `hb alerts` | `PROGRAM` line in `/etc/mdadm.conf`; smartmontools installed, `smartd.conf` replaced, smartd enabled |
| Login banner and SMS | `hb status`, `hb notify` | `/run/motd.d/hb`; state in `/var/lib/hb` |
| Backups | `hb backup` | a restic repository at `backup.repo`; its password in `/etc/hb/secrets` |
| Cleanup report | `hb clean` | nothing while `clean.dry_run` is true; a daily report |

## 0. Look first (changes nothing)

    sudo ./hb config check
    sudo ./hb install plan
    sudo ./hb clean plan          # what cleanup would remove today, with sizes

## 1. Install hb

    sudo dnf install restic
    sudo ./hb install apply

From now on `hb` is on the PATH and root's timers run `/opt/hb`. Edit `hb.toml`
in the checkout as before, then run `sudo ./hb install apply` again: it copies the
changed code and config. `hb install check` (and so the banner) says when the
checkout and the installed copy differ.

## 2. Alerts

    sudo hb alerts apply
    sudo mdadm --monitor --scan --oneshot --test     # one TestMessage per array
    sudo env SMARTD_FAILTYPE=EmailTest SMARTD_DEVICE=/dev/nvme0 SMARTD_MESSAGE="hook test" /opt/hb/hooks/smartd-event
    sudo hb notify events                            # both tests show up here
    sudo hb health status                            # now with an nvme line

## 3. Backup

    sudo hb backup init        # prints the repository password once
    sudo hb backup dry-run     # how much the first run will read; writes nothing
    sudo hb backup run         # the first run takes a while: run it inside tmux
    sudo hb backup status

**Write the password down** and keep it away from the box (a password manager,
paper, the break-glass kit later). Without it the backup can't be read, by
anyone. Then prove a restore works:

    sudo hb backup restic restore latest --target /tmp/restore-test --include /etc/hb
    sudo diff -r /tmp/restore-test/etc/hb /etc/hb && sudo rm -rf /tmp/restore-test

How a run works: the state dump writes package lists, firewall zones, Kubernetes
objects and the like to `/var/lib/hb/state`. Then a read-only btrfs snapshot of
`/` is taken, restic reads the snapshot's files at their real paths (bind-mounted
in a private mount namespace), and the snapshot is deleted. Restored files land
where they came from: `/home/...`, not `/.hb-snapshots/...`.

## 4. SMS

`notify.sms_command` is any command that takes the text on stdin and exits 0 once
the message is queued. Set it in `hb.toml`, run `sudo ./hb install apply`, then:

    sudo hb notify test

Only failures send an SMS, each kind at most once a day, five a day at most.
Everything, failures included, also goes into the banner.

## 5. Banner

    sudo hb status refresh     # the timer does this every 15 minutes
    hb status                  # any user; also shown at SSH login

A failing check sends its SMS on the second refresh in a row, so a pod
restarting during a deploy doesn't page you. RAID and drive problems come
straight from mdadm and smartd, without that delay.

## 6. Cleanup: read the reports for a week

    sudo hb clean report       # written daily at 02:00 by hb-clean.timer

Nothing is removed while `clean.dry_run = true`. If a project shows up that
shouldn't, give it a `.hb-clean` script (which may do nothing), or rename its
build folder. Turning dry-run off is part of the upkeep phase.

## 7. Check

    sudo hb check

## Rolling back

- **Timers:** `sudo systemctl disable --now hb-status.timer hb-backup.timer hb-backup-maintain.timer hb-clean.timer`
- **Alerts:** the old `/etc/mdadm.conf` and `smartd.conf` are under `/var/lib/hb/backup/<run>/`; copy them back, then `sudo systemctl restart mdmonitor` and `sudo systemctl disable --now smartd`.
- **Install:** `sudo rm -rf /opt/hb /usr/local/bin/hb /etc/systemd/system/hb-*.{service,timer} && sudo systemctl daemon-reload`. `/etc/hb` stays; the checkout keeps working with `sudo ./hb`.
- **Backup:** the repository is self-contained; deleting its directory removes it.
