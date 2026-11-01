# Phase 5: comfort

Phase 5 makes the box pleasant to work with from your PCs, without opening
anything new to the internet: drive letters over WireGuard (`hb share`), then
a web shell (`hb webshell`, still being written). Keep a filled-in copy of this
runbook in `local/`.

| Piece | Tool | What changes on the system |
|---|---|---|
| Port 445 in the tunnel's zone | `hb fw apply` | one port in the WireGuard zone |
| Windows shares | `hb share apply` | the samba package; missing share folders in the user's home; `/etc/samba/smb.conf`; `/etc/systemd/system/smb.service.d/hb-share.conf` (IPAddressAllow); smb running, nmb off; the user's Samba password |

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

## The web shell

Not written yet. See the design page: WireGuard-only by default, opened to the
internet for a set time with `hb webshell open 2h`.
