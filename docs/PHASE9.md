# Phase 9: hardening after an outside review

An outside review of hb, cross-checked against the code, led to three parts:

| Part | What | Status |
|---|---|---|
| 9a | Root and users: root stops acting with its own rights on things a user can change | this runbook |
| 9b | SSH: rollback that covers group membership, the effective sshd settings checked | to follow |
| 9c | Honest reporting: backup coverage, a reboot check that can say "unknown", unmanaged tools listed | to follow |

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
