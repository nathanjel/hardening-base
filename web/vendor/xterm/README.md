# xterm.js, vendored

The browser terminal of hb's web shell, served by the daemon from this folder
(same origin, nothing from a CDN). The daemon refuses to start if a file's
sha256 differs from the pin in `lib/hbkit/webshell.py`.

| File | From | npm tarball sha512 (registry `dist.integrity`), checked on download |
|---|---|---|
| `xterm.js`, `xterm.css`, `LICENSE` | `@xterm/xterm` 6.0.0 (`lib/`, `css/`) | matched |
| `addon-fit.js`, `LICENSE.addon-fit` | `@xterm/addon-fit` 0.11.0 (`lib/`) | matched |

Both are MIT-licensed. To update: download the tarballs from
registry.npmjs.org, compare their sha512 with the registry's `dist.integrity`,
copy the same files here, and update the pins.
