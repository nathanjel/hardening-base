# Phase 5: comfort

Phase 5 makes the box pleasant to work with from your PCs: drive letters over
WireGuard (`hb share`), and your shell in a browser (`hb webshell`), over
WireGuard always and from the internet only for a window you open. Keep a
filled-in copy of this runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Port 445 in the tunnel's zone | `hb fw apply` | one port in the WireGuard zone |
| Windows shares | `hb share apply` | the samba package; missing share folders in the user's home; `/etc/samba/smb.conf`; `/etc/systemd/system/smb.service.d/hb-share.conf` (IPAddressAllow); smb running, nmb off; the user's Samba password |
| Web shell | `hb webshell apply` | `/etc/hb/webshell.json` (password hash, code secret); `/etc/systemd/system/hb-webshell.service`, running as the user |
| Its public window | `hb webshell open` | a Service, EndpointSlice, Certificate and Ingress in the cluster; a timer that closes it |

**How the shares work.** Samba can't bind to a WireGuard interface: the
interface has no broadcast or peer address, and Samba's interface probe skips
it. So smbd listens on all addresses, and three independent fences keep it to
the tunnel: 445/tcp is open only in the tunnel's firewalld zone (`hb check`
fails if any other zone opens it), systemd's `IPAddressAllow` on smb.service
makes the kernel drop its traffic to and from anywhere but localhost and the
tunnel's network, and Samba's `hosts allow` says the same. It speaks only SMB
3.1.1 with mandatory signing, which Windows 10 and 11 do by default. There's one user, with a Samba password of its own (not the login
password). Guests, anonymous access, NetBIOS and printers are off.
`map archive = no` keeps files saved from Windows from getting the execute bit,
which git would otherwise report as a mode change. Pods and containers can reach the host's
addresses through the trusted and docker zones; the other two fences turn
them away.

**Risk.** Low: nothing is exposed beyond the tunnel, and SSH isn't touched. The
firewall change uses hb fw's revert timer as before.

## 0. Before you start

- The tunnel works from each PC that should get drives (phase 3).
- In `hb.toml`: `share.user`, `share.shares` (`"NAME PATH"`, `~` is the user's
  home), and `"445/tcp"` added to the WireGuard zone's `ports` under
  `fw.zones`.

## 1. Install the new code and config

    sudo ./hb install apply

## 2. Open 445 in the tunnel's zone

    sudo hb fw plan               # the WireGuard zone gains 445/tcp
    sudo hb fw apply

From a new session (over the tunnel is fine): `sudo hb fw confirm`.

## 3. The shares

    sudo hb share plan
    sudo hb share apply           # installs samba, writes the config, starts smb,
                                  # asks for the Samba password at the end

Pick a new password for Samba and keep it in your password manager. It is
only ever sent inside the tunnel. `sudo hb share password` changes it later.

## 4. On each Windows PC

With the tunnel up, in PowerShell (not as administrator):

    cmdkey /add:SERVER_WG_ADDRESS /user:YOU /pass
    net use W: \\SERVER_WG_ADDRESS\NAME /persistent:yes

`cmdkey` asks for the Samba password and keeps it in Credential Manager, so
the drive reconnects at sign-in once the tunnel is up. Or do the same in File
Explorer: This PC, Map network drive, "Connect using different credentials".

Then:

    sudo hb check

## Living with it

- A new share: add it to `share.shares`, `sudo ./hb install apply`,
  `sudo hb share apply`, then map it on the PC.
- The drive shows as disconnected while the tunnel is down, and comes back
  when the tunnel does.
- `hb check` flags 445 open in any zone besides the tunnel's, the unit filter
  missing, and any Samba account other than `share.user`.

## Rolling back

    sudo systemctl disable --now smb
    sudo rm /etc/systemd/system/smb.service.d/hb-share.conf && sudo systemctl daemon-reload

Fedora's sample `smb.conf` is kept under `/var/lib/hb/backup/<run>/`. Take 445
out of the zone's `ports` and run `hb fw apply`; `sudo dnf remove samba` if you
want the package gone too.

# Part 2: the web shell

**How it works.** A small daemon (`lib/hbkit/webshell.py`, standard library
only) runs as you and listens on the WireGuard address only. After a login it
opens your shell in tmux (session `web`, shared with SSH's tmux if one runs),
shown by vendored xterm.js (sha256-pinned, same origin). Over the tunnel it is
plain HTTP at `http://<wg address>:7681`, encrypted by WireGuard.

The public window doesn't open a port. `hb webshell open 2h` applies an
Ingress for `webshell.host` (with a cert-manager certificate) whose
EndpointSlice points at the WireGuard address, so the existing ingress on 443
carries it. Pods already reach the host through the trusted zone. The daemon
answers the ingress only while the window lasts, only for that name, and only
over HTTPS. A timer runs `hb webshell close` at the end.

**Guards.** A password of its own (scrypt) plus a 6-digit code from its own
authenticator entry, each code used once. 5 failed logins per address in 15
minutes; after 20 in an hour, logins stop for everyone until `hb webshell
unlock`, and `hb check` fails (an SMS). Sessions last 12 hours at most and end
after 30 idle minutes; the cookie is HttpOnly and SameSite=Strict (`__Host-`
and Secure over HTTPS). Every POST and the WebSocket must come from the site's
own Origin. No inline script, no framing. Request, body and frame sizes are
capped, and at most 3 terminals can be open. The log names who logged in or
failed and from where, never what was typed or shown.

The daemon reads no config: root writes its settings into the unit, and
systemd hands it the password hash and code secret (`LoadCredential`), so
those stay root-only on disk. It isn't sandboxed, because the shell it opens
is yours and may run sudo; its protection is the login and the window.

**Risk.** Over WireGuard, low. The public window puts your shell one password
and one code away from anyone, so keep it short.

## 5. Port 7681 in the tunnel's zone

Add `"7681/tcp"` to the WireGuard zone's `ports` in `hb.toml`, then:

    sudo ./hb install apply
    sudo hb fw apply              # and hb fw confirm from a new session

## 6. The web shell

In `hb.toml`: `webshell.user` (and, for the public window, `host`,
`ingress_from`, `issuer`, `middlewares`). Then:

    sudo hb webshell plan
    sudo hb webshell apply        # asks for the password, then shows a QR code for the app

Use a new password (12 characters or more). The app gets a second entry,
`<host>:<you>-web`, separate from SSH's. On a PC with the tunnel up, open
`http://<wg address>:7681`, log in, and you're in tmux session `web`.

## 7. The public window (optional)

It needs a DNS name for `webshell.host` pointing at the server.

    sudo hb webshell open 30m     # the first time also waits for the certificate

Open `https://<host>/` from another network (a phone on mobile data), log in,
then `sudo hb webshell close`, or let the timer do it. `sudo hb webshell
status` shows the window, sessions and the last login.

Then:

    sudo hb check

## Living with the web shell

- Closing the tab leaves tmux running; the next login attaches to it again.
  `exit` in the shell ends the tmux session.
- A new phone: `sudo hb webshell password` (a new password and a new app entry).
- Locked out after failed attempts: `sudo hb webshell unlock`.
- Restarting the daemon (or `hb install apply` plus a restart) leaves the tmux
  session alone (KillMode=process).

## Rolling back the web shell

    sudo hb webshell close
    sudo systemctl disable --now hb-webshell
    sudo rm /etc/systemd/system/hb-webshell.service /etc/hb/webshell.json && sudo systemctl daemon-reload
    sudo /snap/bin/microk8s kubectl delete service,endpointslice,certificate hb-webshell -n <namespace>

Take 7681 out of the zone's `ports` and run `hb fw apply`.
