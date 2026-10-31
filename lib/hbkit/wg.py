"""WireGuard settings for hb-wg: check [wg] in hb.toml, render wg-quick's file,
and print what a PC pastes into its own WireGuard app.

Peers are lines of "NAME ADDRESS PUBLIC-KEY". Each PC makes its own key pair
(the WireGuard app's "Add empty tunnel"), so private keys never leave the PC;
the server's private key stays in its root-only file and only appears in the
rendered wg-quick file, which hb-wg writes straight to disk.

  wg.py validate          one line about the peers, or the problems (exit 2)
  wg.py render KEYFILE    the wg-quick file
  wg.py diff FILE         what writing the rendered file would change
  wg.py peer NAME PUBKEY  the lines NAME pastes into its tunnel
"""
import base64
import binascii
import ipaddress
import os
import re
import sys
from dataclasses import dataclass

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
IFACE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
HEADER = "# Managed by hb-wg from hb.toml [wg]; changes made here are overwritten."


@dataclass(frozen=True)
class Peer:
    name: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    key: str

    @property
    def allowed(self):
        return f"{self.ip}/{self.ip.max_prefixlen}"


def valid_key(key):
    """A WireGuard key: 32 bytes, base64."""
    try:
        return len(key) == 44 and len(base64.b64decode(key, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def parse(wg):
    """(interface address, peers) from the [wg] table; ValueError naming every problem."""
    errors = []
    try:
        iface = ipaddress.ip_interface(str(wg["address"]))
        if "/" not in str(wg["address"]):
            raise ValueError
    except ValueError:
        raise ValueError(f"wg.address {wg['address']!r} is not an address with a prefix, e.g. 10.77.0.1/24")
    net = iface.network
    if iface.ip in (net.network_address, getattr(net, "broadcast_address", None)) or net.num_addresses < 4:
        errors.append(f"wg.address {iface} leaves no room for peers")
    if not IFACE.match(str(wg["interface"])):
        errors.append(f"wg.interface {wg['interface']!r} is not an interface name")
    port = wg["port"]
    if not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append(f"wg.port {port!r} is not a port number")

    peers, names, ips, keys = [], set(), {iface.ip}, set()
    for line in wg["peers"]:
        parts = str(line).split()
        if len(parts) != 3:
            errors.append(f"peer {line!r}: want 'NAME ADDRESS PUBLIC-KEY'")
            continue
        name, addr, key = parts
        if not NAME.match(name):
            errors.append(f"peer {name!r}: names are lowercase letters, digits and dashes")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            errors.append(f"peer {name}: {addr!r} is not an address")
            continue
        if ip not in net or ip in (net.network_address, getattr(net, "broadcast_address", None)):
            errors.append(f"peer {name}: {ip} is not a usable address in {net}")
        if not valid_key(key):
            errors.append(f"peer {name}: the public key is not a WireGuard key (44 characters of base64)")
        for seen, val, what in ((names, name, "name"), (ips, ip, "address"), (keys, key, "key")):
            if val in seen:
                errors.append(f"peer {name}: {what} used twice")
            seen.add(val)
        peers.append(Peer(name, ip, key))
    if errors:
        raise ValueError("; ".join(errors))
    return iface, peers


def render(wg, private_key):
    iface, peers = parse(wg)
    lines = [HEADER, "[Interface]", f"Address = {iface}", f"ListenPort = {wg['port']}",
             f"PrivateKey = {private_key}"]
    for p in peers:
        lines += ["", f"# {p.name}", "[Peer]", f"PublicKey = {p.key}", f"AllowedIPs = {p.allowed}"]
    return "\n".join(lines) + "\n"


def read_conf(text):
    """(interface settings, {name: (allowed, key)}) from a file render() wrote."""
    settings, peers, pending, section, cur = {}, {}, None, None, None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            pending = line.lstrip("#").strip()   # a comment names the peer after it
            continue
        if line in ("[Interface]", "[Peer]"):
            section = line[1:-1]
            if section == "Peer":
                cur = pending or f"peer{len(peers) + 1}"
                peers[cur] = {}
            pending = None
            continue
        if "=" not in line:
            continue
        k, v = (s.strip() for s in line.split("=", 1))
        if section == "Interface":
            settings[k] = v
        elif section == "Peer":
            peers[cur][k] = v
    return settings, {n: (d.get("AllowedIPs", ""), d.get("PublicKey", "")) for n, d in peers.items()}


def diff(old_text, new_text):
    """Human lines for what replacing old_text with new_text changes; keys stay out."""
    if old_text is None:
        return ["new file"]
    old_s, old_p = read_conf(old_text)
    new_s, new_p = read_conf(new_text)
    out = []
    for k in ("Address", "ListenPort"):
        if old_s.get(k) != new_s.get(k):
            out.append(f"{k} {old_s.get(k, '-')} → {new_s.get(k)}")
    if old_s.get("PrivateKey") != new_s.get("PrivateKey"):
        out.append("server key changed")
    for n in sorted(set(old_p) | set(new_p)):
        if n not in new_p:
            out.append(f"- peer {n}")
        elif n not in old_p:
            out.append(f"+ peer {n} {new_p[n][0]}")
        elif old_p[n] != new_p[n]:
            out.append(f"~ peer {n}")
    if not out and old_text != new_text:
        out.append("layout only")
    return out


def peer_text(wg, name, server_public):
    iface, peers = parse(wg)
    match = [p for p in peers if p.name == name]
    if not match:
        raise KeyError(name)
    p = match[0]
    host = str(wg["endpoint"]) or "<this server's public name>"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return "\n".join([
        f"On {name}, edit the tunnel you made with \"Add empty tunnel\" in the WireGuard app.",
        "Keep its first two lines ([Interface] and PrivateKey = ...) and add these below them:",
        "",
        f"Address = {p.allowed}",
        "",
        "[Peer]",
        f"PublicKey = {server_public}",
        f"AllowedIPs = {iface.ip}/{iface.ip.max_prefixlen}",
        f"Endpoint = {host}:{wg['port']}",
        "PersistentKeepalive = 25",
        "",
        f"Only traffic for this server ({iface.ip}) goes through the tunnel.",
    ]) + "\n"


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    from hbkit import config
    wg = config.load()["wg"]
    verb = argv[1] if len(argv) > 1 else ""
    try:
        if verb == "validate":
            _, peers = parse(wg)
            print(f"{len(peers)} peers" + (": " + ", ".join(f"{p.name} {p.ip}" for p in peers) if peers else ""))
        elif verb == "render" and len(argv) == 3:
            with open(argv[2]) as f:
                sys.stdout.write(render(wg, f.read().strip()))
        elif verb == "diff" and len(argv) == 3:
            old = None
            if os.path.exists(argv[2]):
                with open(argv[2]) as f:
                    old = f.read()
            new = sys.stdin.read()
            print(", ".join(diff(old, new)) or "no change")
        elif verb == "peer" and len(argv) == 4:
            sys.stdout.write(peer_text(wg, argv[2], argv[3]))
        else:
            print(__doc__.strip(), file=sys.stderr)
            return 2
    except ValueError as e:
        print(e)
        return 2
    except KeyError as e:
        print(f"no peer named {e.args[0]} in wg.peers")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
