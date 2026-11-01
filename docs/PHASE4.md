# Phase 4: doors

Phase 3 gave you a private way in. Phase 4 decides who may use the public one
and how: keys that only root can change, a 6-digit code after the key from the
internet (the key alone over WireGuard), and a rescue account with a kit for one
trusted person. Keep a filled-in copy of this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Rescue account and login alert | `hb breakglass apply` | a user (fixed uid, in wheel, password locked); `/etc/systemd/system/user@<uid>.service.d/hb-breakglass.conf` |
| Codes | `hb totp enrol` | `/etc/hb/secrets/totp/<user>` |
| Who may log in, and how | `hb ssh apply` | group `hb-ssh`; `/etc/ssh/authorized_keys/<user>`; `/etc/ssh/sshd_config.d/10-hb-ssh.conf`; the auth step of `/etc/pam.d/sshd`; sshd reloads |
| The kit | `hb breakglass kit` | the rescue key, password and recovery codes; a restic key for the kit |

**How a login works afterwards.** sshd reads keys only from
`/etc/ssh/authorized_keys/<user>` (root's files, so nothing running as you can
add a key) and lets in only members of `hb-ssh`. From the internet it then asks
for a code: the prompt says `Password:` (PAM's word, not ours), and you type the
6 digits from the app, or one recovery code. From the networks in
`ssh.key_only_from` the key alone is enough. A wrong code or any error refuses
the login; sshd only shows the prompt to someone whose key it already accepted.

**Lockout risk.** This is the phase that can lock you out, so `hb ssh apply`
undoes itself after `ssh.revert_minutes` unless confirmed from a new session,
and refuses to start when the person running it has no key in `ssh.keys` or
isn't enrolled. Sessions already open stay open. Work inside tmux, keep a second
session open, and know the other ways in: WireGuard (key only), the provider's
console (the rescue account's password), the provider's rescue boot.

## 0. Before you start

- An authenticator app on your phone (Aegis, 2FAS, Google or Microsoft
  Authenticator, a password manager's TOTP field: any RFC 6238 app).
- A USB stick, a printer, and the person who will hold the kit.
- Optional, for a QR code instead of typing the key: `sudo dnf install qrencode`.

## 1. Install the new code and config

    sudo ./hb install apply

The banner shows the new pieces as pending until the steps below are done.

## 2. The rescue account

    sudo hb breakglass plan
    sudo hb breakglass apply      # account, alert

Its password stays locked and it has no key until step 5.

## 3. Your code

    sudo hb totp enrol YOU

Scan the QR code (or type the key) into the app, type the code it shows, and
keep the 10 recovery codes off the server, e.g. in your password manager. Do
this for everyone in `ssh.keys`.

## 4. SSH

    sudo hb ssh plan
    sudo hb ssh apply             # starts the revert timer

Keep that session. Open a NEW one from the internet: the key, then the code at
`Password:`. If you use WireGuard, open one over it too: the key alone. If both
log in, run in one of them:

    sudo hb ssh confirm

If one doesn't, do nothing: the old files come back by themselves, or run
`sudo hb ssh revert` in the session you still have.

## 5. The kit

    sudo hb breakglass kit

It writes `~/hb-kit-<date>/` (yours, mode 700): `rescue.key`, `kit.html`,
`kit.txt`. Copy the folder to your PC, then delete it on the server
(`hb check` reminds you while it is there). Print `kit.html`; put `rescue.key`
and `kit.html` on the USB stick.

## 6. Test the kit

On a Windows PC, with only the stick and the page, follow the page: copy the key,
connect, type the passphrase and one recovery code (cross it out), `sudo -i`
with the account password, `exit`. You get the login SMS, and
`sudo hb breakglass status` shows the login. Then test the console path once:
the provider's console (IPMI, serial over LAN), log in as the rescue account
with its password, `exit`.

Seal the page and the stick in an envelope and hand it over.

    sudo hb check

## Living with it

- Each new connection from the internet asks for a code. Tools that open many
  (VS Code Remote, scripts) are happier over WireGuard, or with ssh's
  `ControlMaster` reusing one connection.
- A new PC or key: add a line to `ssh.keys`, `sudo ./hb install apply`,
  `sudo hb ssh apply` and confirm.
- A recovery code used shows in the banner; `sudo hb totp codes YOU` makes 10
  new ones. A new phone: `sudo hb totp enrol YOU` again.
- The rescue alert fires when the account's first session starts. A login
  while another rescue session is still open (the console you tested from,
  say) adds no SMS, and `hb notify` sends `breakglass.login` at most once per
  `notify.repeat_hours`. Log out of every rescue session when you're done.
- After the kit has been used, or once a year: `sudo hb breakglass kit` makes a
  new one and retires the old (key, password, codes, restic key).
- Codes depend on the clock; `hb totp check` warns when NTP isn't synchronised.

## Rolling back

- **SSH, before confirm:** `sudo hb ssh revert`. After confirm, back to keys
  only: `ssh.codes = false`, `sudo ./hb install apply`, `sudo hb ssh apply`.
  Entirely: copy `/etc/pam.d/sshd` back from `/var/lib/hb/backup/<run>/`, delete
  `/etc/ssh/sshd_config.d/10-hb-ssh.conf`, `sudo systemctl reload sshd`
  (sshd then reads `~/.ssh/authorized_keys` again).
- **Rescue account:** `sudo userdel -r <user>`, delete its drop-in directory
  under `/etc/systemd/system/` and `/etc/ssh/authorized_keys/<user>`,
  `sudo systemctl daemon-reload`, and remove the kit's restic key
  (`restic key list`, `restic key remove <id>`).
