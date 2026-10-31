"""hb configuration: built-in defaults overlaid by one host TOML file.

The host file is the first that exists of: $HB_CONFIG, /etc/hb/hb.toml,
<repo>/hb.toml. Defaults are chosen so that a missing key never changes
anything on the system: empty lists, and "" for "not managed".
"""
import copy
import os
import tomllib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

DEFAULTS = {
    "harden": {
        "remove_accounts": [],
        "remove_files": [],
        "permit_root_login": "",
    },
    "k8s": {
        "flavour": "microk8s",
        "nodeport_addresses": [],
        "token_off_namespaces": [],
    },
    "health": {
        "containers": [],
        "urls": [],
        "mounts": [],
        "registry": "",
        "asterisk_container": "",
        "disk_warn_pct": 80,
        "disk_fail_pct": 90,
    },
    "snapshot": {
        "dir": "/.hb-snapshots",
        "keep_days": 14,
    },
}


def candidates():
    env = os.environ.get("HB_CONFIG")
    return [env] if env else ["/etc/hb/hb.toml", os.path.join(REPO, "hb.toml")]


def path():
    """The host file in use, or None when there is none (defaults only)."""
    for p in candidates():
        if os.path.isfile(p):
            return p
    return None


def read_host_file():
    p = path()
    if not p:
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def _merge(base, over):
    for key, val in over.items():
        if isinstance(base.get(key), dict) and isinstance(val, dict):
            _merge(base[key], val)
        else:
            base[key] = val


def load():
    cfg = copy.deepcopy(DEFAULTS)
    _merge(cfg, read_host_file())
    return cfg


def get(cfg, dotted):
    """Value at a dotted key such as "k8s.nodeport_addresses"; KeyError if absent."""
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise KeyError(dotted)
        node = node[part]
    return node


def unknown_keys(data, defaults=DEFAULTS, prefix=""):
    """Dotted keys in a host file that hb doesn't know, usually typos."""
    found = []
    for key, val in data.items():
        if key not in defaults:
            found.append(prefix + key)
        elif isinstance(val, dict) and isinstance(defaults[key], dict):
            found += unknown_keys(val, defaults[key], f"{prefix}{key}.")
    return found
