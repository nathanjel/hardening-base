# Phase 9: hardening after an outside review

An outside review of hb, cross-checked against the code, led to three parts:

| Part | What | Status |
|---|---|---|
| 9a | Root and users: root stops acting with its own rights on things a user can change | this runbook |
| 9b | SSH: rollback that covers group membership, the effective sshd settings checked | this runbook |
| 9c | After an outage: an SMS route that doesn't depend on Kubernetes, alerts that admit they failed, microk8s that keeps retrying, evicted pods as a warning, honest cleanup figures | this runbook |
| 9d | Honest reporting: backup coverage, a reboot check that can say "unknown", unmanaged tools listed | to follow |

Keep a filled-in copy of this runbook in `local/`.

## 9a: root and users

Several of hb's root jobs touch things that belong to a user: their projects,
their caches, their tmux, a folder in their home. The rule from now on: **root
doesn't use its own rights on anything a user can change. It works in folders
only root can write, or it acts as that user.**

| Piece | Tool | What changes |
|---|---|---|
| Writing files | every tool (`util.write_atomic`) | temporary files are new and randomly named; permissions are set on the open file |
| Public window | `hb webshell` | the window's end moves from the daemon's folder to `/run/hb-webshell-public`, root's. The daemon only reads it, and a reboot clears it |
| Cleanup | `hb clean` | projects and caches are handled as the owner the plan saw, deletions included. A folder swapped after the plan is left alone and reported |
| Busy check | `busy.d/tmux` | each tmux server is asked by a client running as the owner of its socket, with a bare environment |
| Break-glass kit | `hb breakglass kit` | the folder stays root's until the kit is complete, then it is handed over, without following links |
| Getting files back | `hb restore get` | the default folder is new and randomly named: `/var/tmp/hb-restore-<now>-<random>` |

**What you may notice in `hb clean`:**
- A repo owned by root is skipped, with a note.
- A build folder or cache entry that holds another user's subfolder, typically a
  container's build output, is kept and named in the notes. Its owner can't empty
  it, so remove it by hand with sudo. Other people's plain files in a folder of
  the owner's still go.
- Read-only folders of the owner's (Go's module cache, pnpm) still go: they get
  write permission back for a second try.

**Risk.** Low. The web shell daemon restarts once, and the tmux session stays. An
open public window closes at that restart, so close it first. Timers keep running
and no config changes.

### 0. Before you start

    sudo hb webshell status        # window: WireGuard only; if public: sudo hb webshell close

### 1. Install

    sudo ./hb install apply        # y to code
    sudo hb webshell apply         # service: runs older code than is installed; y

### 2. Check

    sudo hb check                  # as before

A `public` file left in `/var/lib/hb-webshell/` by an older version is ignored.
Delete it if it's there.

### 3. The public window

    sudo hb webshell open 30m
    ls -l /run/hb-webshell-public  # -rw-r--r-- root root
    sudo hb webshell status        # window: public at <host> until ...
    sudo hb webshell close         # closed: WireGuard only; the file is gone

### 4. The busy check

In a tmux pane of your own, run `sleep 300`. Then, elsewhere:

    sudo hb upgrade status         # busy now: ... tmux session <name> runs sleep

### 5. Getting a file back

    sudo hb restore get /etc/hb/hb.toml    # restored into /var/tmp/hb-restore-<now>-<random>
    sudo sh -c 'rm -r /var/tmp/hb-restore-*'

### 6. Cleanup

    sudo hb clean plan             # the same work as before, plus any "kept" notes

If `clean.dry_run` is still true, this is the moment to read `sudo hb clean report`
and decide about turning it off.

The kit has nothing to run now. The next `hb breakglass kit` uses the new code,
and making one just to test it would void the one you have.

### Tests

`tests/test_boundary.py` runs these cases with two real uids in a user namespace.
It needs subordinate uids in `/etc/subuid` and `/etc/subgid`, and is skipped without
them. Worth running on each new kind of server.

### Rolling back

Close any public window, check out the previous commit, then:

    sudo ./hb install apply
    sudo hb webshell apply

## 9b: SSH

`hb ssh` promised "key from root's file, then a code; key alone over WireGuard",
and checked that promise by comparing its own files' text. Two gaps:

- **The rollback.** The `hb-ssh` group changed before the revert timer started.
  A change to the group alone started no timer, and a revert brought the files
  back but not the members.
- **sshd's own view.** sshd keeps the first value it reads for most settings, so
  hb's `10-` drop-in wins against later files' plain lines. But a `Match` block in
  a later file still wins, a file that sorts before `10-` comes first, and
  `AllowGroups` lines add up rather than the first one winning. hb never
  said which way of accepting keys sshd should leave out, either.

| Piece | What changes |
|---|---|
| Rollback | the timer starts before anything changes, the group's members are saved with the files, a revert puts them back (and removes the group if apply made it). A change to the group alone waits for `hb ssh confirm` too |
| The drop-in | five more lines: no key command, no principals file or command, no certificate authorities, no host-based login |
| sshd's own view | `apply` (before it reloads sshd) and `check` run `sshd -T` for each user, once per kind of client: from the internet (IPv4 and IPv6) and from each `ssh.key_only_from` network, with the local address this box would answer on. Any difference from what hb promises fails, with the files that set it |

**Risk.** Medium, as with any sshd change: one apply with the revert timer, so
keep a session open and confirm from a new one.

### 0. Before you start

    sudo ls /etc/ssh/sshd_config.d/                   # which drop-ins exist besides hb's
    sudo sh -c "grep -il '^[[:space:]]*match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
                                   # sh -c: the folder is root's, so the * has to expand as root

Work in tmux and keep a second session open.

### 1. Install

    sudo ./hb install apply        # y to code
    sudo hb ssh check              # pending: /etc/ssh/sshd_config.d/10-hb-ssh.conf

### 2. Apply

    sudo hb ssh plan               # + AuthorizedKeysCommand none, ... (five lines)
    sudo hb ssh apply              # y; it asks sshd first, then reloads

If sshd would do something else, apply says what and where, and puts
everything back at once.

### 3. Confirm from new sessions

From the internet (key, then the code at the Password: prompt), and over
WireGuard (key only). In one of them:

    sudo hb ssh confirm

### 4. Check

    sudo hb ssh check              # ok: <users>; key + code, key only from <networks>
    sudo hb check

From now on `hb check` asks sshd every time. A drop-in that some package adds
later and that changes one of these settings shows up as a failure, with its file
named. `sudo hb ssh status` lists every difference.

### Rolling back

Within the revert time: `sudo hb ssh revert`. Later: check out the previous
commit, `sudo ./hb install apply`, `sudo hb ssh apply` (same timer, same confirm).

## Snapshots on a busy disk

A btrfs snapshot of `/` keeps every block that was deleted or rewritten after
it, on the same disk. On a box whose disk churns (build caches, container
images, a cleanup), a few days of snapshots can hold more than the cleanup
frees. Moving them to the backup share isn't possible: a snapshot is part of
the filesystem it was taken from, and sending one elsewhere needs a parent kept
locally. The off-disk copy with its own retention is the restic backup.

| Setting | Effect |
|---|---|
| `upgrade.snapshot_days = 0` | no snapshot before the nightly upgrade, and any old `upgrade-*` ones go at the next run. The night's backup (before the upgrade) is the way back |
| `snapshot.keep_days = 1` | snapshots you take by hand (`hb snapshot create`) show as a warning in `hb check` after a day |
| `hb snapshot delete NAME` | removes one now |

`hb backup` still reads from a snapshot it deletes when the run ends; that one
costs little, because it only lives for the length of the backup.

    sudo ./hb install apply        # y to code and config
    sudo hb snapshot list
    sudo hb snapshot prune         # everything older than keep_days
    sudo hb snapshot delete <name> # any newer one, as listed
    sudo btrfs subvolume sync /    # waits until btrfs has freed the space
    df -h /

## 9c: after an outage

A build cache in a user's project filled `/` for a few minutes. Kubernetes
evicted pods and started replacements, then kubelite died, and snapd's unit
gave up restarting it after five failures in a second. hb saw it within 15
minutes, but its SMS command ran through `kubectl exec`, so the text never went
out, and `hb notify check` went on saying ok after it gave up. Once kubelite was
back, `hb health` failed for good on the evicted pods' records.

| Piece | Tool | What changes |
|---|---|---|
| A second SMS route | `hb notify`, `hooks/sms-supervoip` | `notify.sms_fallback`, tried when `sms_command` fails. The hook sends through supervoip.pl's REST API with a token from `/etc/hb/secrets/supervoip-token`; `--sender` takes one of the account's SMS sender names. `hb notify test --fallback` tests that route alone |
| Alerts that admit it | `hb notify check` | warns for 24 hours after an SMS was dropped, or needed the fallback |
| Keep retrying | `hb k8s`, item `restart` | a systemd drop-in for each daemon in `k8s.keep_restarting`: retry every 10 s, no limit. Live at once; nothing restarts |
| Evicted pods | `hb health` | an evicted pod whose replacement runs is a warning with the count and the command to clear it, no longer a failure |
| Cleanup figures | `hb clean` | the unused-image figure is capped at what Docker counts as reclaimable (images share layers); a run by hand writes the report too, so `hb clean check` and the digest show it |

**Risk.** Low. Nothing restarts. The fallback costs one SMS to test.

### 0. Before you start

A token for the SMS provider in a root-only file. The hook reads the first line:

    sudo sh -c 'umask 077; cat > /etc/hb/secrets/supervoip-token'    # paste, Enter, Ctrl-D

In `hb.toml`: `notify.sms_fallback` and `k8s.keep_restarting` (see `hb.toml.example`).
`sudo /opt/hb/hooks/sms-supervoip --list-senders` shows the account's sender names
(after the install below).

### 1. Install

    sudo ./hb install apply        # y to code and config

### 2. The second route

    sudo hb notify test --fallback # sent by notify.sms_fallback; one SMS arrives
    sudo hb notify check           # ok: SMS for failures (with a fallback), ...

### 3. Keep retrying

    sudo hb k8s plan               # would change restart: kubelite: no drop-in; ...
    sudo hb k8s apply              # y to restart
    systemctl show snap.microk8s.daemon-kubelite -p StartLimitIntervalUSec -p RestartUSec
                                   # StartLimitIntervalUSec=0, RestartUSec=10s

### 4. Check

    sudo hb check
    sudo hb clean plan             # docker: the capped image figure

### Rolling back

Empty `notify.sms_fallback` and `k8s.keep_restarting` in `hb.toml`, then
`sudo ./hb install apply`, and remove the drop-ins:
`sudo sh -c 'rm /etc/systemd/system/snap.microk8s.daemon-*.service.d/10-hb-keep-restarting.conf'`,
`sudo systemctl daemon-reload`.

## A second review of 9a to 9c

| Piece | Tool | What changes |
|---|---|---|
| Break-glass kit | `hb breakglass kit` | the whole kit is made in root's own folder first. Only then is the destination's parent opened from `/` one name at a time, refusing links, and the kit's folder created in it, checked to be this run's (root's, empty) and filled. Only that folder and the files written into it are handed over, each through its own descriptor; a failed run hands over nothing. A `--to` whose path goes through a link is refused |
| sshd's own view | `hb ssh` | a client the box has no route to (no IPv6, say) is skipped as before, but a probe that fails for any other reason fails the check, and so does a check that reached no client at all |
| SMS fallback | `hooks/sms-supervoip` | only an answer that lists the message in `queuedMessages` counts as sent; a missing, empty or malformed one is a failure, so `hb notify` keeps the SMS and tries again |
| Evicted pods | `hb health` | an evicted pod is a warning only once its workload runs again (a pod of the same controller, or the same Deployment after a rollout, is up or done); otherwise it fails like any pod that is down |

    sudo ./hb install apply        # y to code
    sudo hb notify test --fallback # sent by notify.sms_fallback: the real API confirms the queue
    sudo hb ssh check              # ok, as before
    sudo hb check

A third and a fourth review found three more, also fixed:

| Piece | Tool | What changes |
|---|---|---|
| Break-glass kit | `hb breakglass kit` | the destination folder is made and checked first, before the key, the password, the codes or the backup key change, so a `--to` that can't take the kit fails while the old kit still works. Every new secret is written down in root's folder (`/var/lib/hb/breakglass/kit-.../secrets.json`) before it goes live, and the recovery codes the moment they exist. Until a whole kit exists, `hb breakglass check` fails and says where that folder is; once one exists but couldn't be delivered, it stays there and the check reminds you |
| Evicted pods | `hb health` | an evicted pod is a warning only when its controller has all the pods it wants available again (the Deployment above a ReplicaSet, a StatefulSet's replicas, a DaemonSet's nodes, a Job's completions). Another pod of the same controller being up isn't enough |

Don't make a kit just to test it: a new kit voids the one you have.
`tests/test_boundary.py` covers the kit with two real uids, including a folder above
the kit being swapped for a link while it is made.
