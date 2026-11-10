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
        "sysctl": [],
        "llmnr": "",
        "x11_forwarding": "",
        "journal_max_use": "",
    },
    "k8s": {
        "flavour": "microk8s",
        "nodeport_addresses": [],
        "token_off_namespaces": [],
        "freeze_certs": False,
        "cluster_agent_bind": "",
        "keep_restarting": [],
        "linger_root": False,
        "block_metadata": False,
    },
    "health": {
        "containers": [],
        "urls": [],
        "mounts": [],
        "registry": "",
        "asterisk_container": "",
        "disk_warn_pct": 80,
        "disk_fail_pct": 90,
        "reboot_fail_days": 7,
        "cert_warn_days": 14,
        "nvme_wear_warn_pct": 80,
    },
    "snapshot": {
        "dir": "/.hb-snapshots",
        "keep_days": 14,
    },
    "install": {
        "timers": [],
    },
    "notify": {
        "name": "",
        "sms_command": [],
        "sms_fallback": [],
        "sms_per_day": 5,
        "repeat_hours": 24,
        "retry_minutes": 60,
    },
    "alerts": {
        "mdadm": False,
        "smartd": False,
    },
    "backup": {
        "repo": "",
        "password_file": "/etc/hb/secrets/restic-password",
        "require_mount": "",
        "paths": [],
        "exclude": [],
        "exclude_if_present": [".hb-nobackup"],
        "keep_daily": 7,
        "keep_weekly": 5,
        "keep_monthly": 12,
        "warn_hours": 26,
        "fail_hours": 50,
        "read_data_percent": 10,
        "restic_version": "",   # "": the restic on PATH; a version: restic's own release, by hb install
        "restic_sha256": "",
        "dumps": [],            # hb dump: databases dumped before each backup
        "dumps_max_mb": 10240,  # all of one run's dumps together
    },
    "restore": {
        "sample_files": 200,
        "max_file_mb": 200,
        "must_have": ["/etc/hb/hb.toml", "/var/lib/hb/state"],
        "drill_days": 92,
    },
    "rebuild": {
        # copied from the snapshot's /etc and /usr/local where the box has none
        "files": ["/etc/yum.repos.d/*.repo", "/etc/pki/rpm-gpg/*", "/etc/docker/daemon.json",
                  "/usr/local/bin/*", "/usr/local/sbin/*"],
        "data": [],     # empty: backup.paths without /etc, /usr/local and hb's own state
        # made by microk8s and its add-ons; every other namespace is yours
        "skip_namespaces": ["kube-system", "kube-public", "kube-node-lease", "ingress", "cert-manager",
                            "container-registry", "metallb-system", "observability"],
    },
    "inventory": {
        "drift_ignore": [],     # regexes; drift lines matching one are left out
    },
    "disk": {
        "show_gb": 2,
        # where a big folder untouched for stale_days is worth a mention
        "stale_roots": ["/home", "/root", "/srv", "/opt", "/var/tmp", "/var/lib/hb/backup"],
        "stale_days": 30,
        "stale_gb": 1,
        "stale_ignore": [],     # globs: the folder and everything under it
        "skip": [],             # folders never walked (hb's snapshots never are)
    },
    "clean": {
        "dry_run": True,
        "users": [],
        "project_roots": [],
        "idle_days": 14,
        "venv_idle_days": 90,
        "build_dirs": ["target", "build", "dist", "__pycache__", ".pytest_cache",
                       ".mypy_cache", "cmake-build-*", "node_modules"],
        "cache_idle_days": 30,
        "docker": False,
        "docker_container_days": 7,
        "docker_image_days": 14,
        "docker_build_cache": "15GB",
        "heavy_weekday": 6,
        # microk8s' registry addon on hostpath-storage; "" to not watch a registry
        "registry_dir": "/var/snap/microk8s/common/default-storage/container-registry-registry-claim-*",
        "registry_warn": "10GB",
    },
    "wg": {
        "interface": "wg0",
        "address": "",
        "port": 51820,
        "endpoint": "",
        "peers": [],
    },
    "fw": {
        "revert_minutes": 5,
        "zones": {},
    },
    "probe": {
        "host": "",
        "expect_tcp": [],
    },
    "ssh": {
        "keys": [],
        "codes": False,
        "key_only_from": [],
        "revert_minutes": 5,
    },
    "totp": {
        "issuer": "",
    },
    "breakglass": {
        "user": "",
        "uid": 4700,
        "host": "",
        "note": "",
        "test_days": 180,
    },
    "share": {
        "user": "",
        "shares": [],
    },
    "webshell": {
        "user": "",
        "port": 7681,
        "host": "",
        "ingress_from": [],
        "ingress_class": "public",
        "namespace": "default",
        "issuer": "",
        "middlewares": "",
        "max_hours": 12,
    },
    "upgrade": {
        "enabled": False,
        "window_end": "07:00",
        "snaps": [],
        "refresh_snaps": True,
        "snapshot_days": 3,
        "force_after_days": 0,
        "release": "",
        "security_only": False,
        "repos": [],
        "after": [],
        "reboot": "idle",
    },
    "busy": {
        "idle_minutes": 60,
        "max_load": 2.0,
        "processes": ["make", "cargo", "rustc", "cc1", "cc1plus", "go", "gradle", "mvn", "npm", "pytest",
                      "buildkitd", "dnf", "rpm"],
    },
    "digest": {
        "reminders": [],
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
    """Dotted keys in a host file that hb doesn't know, usually typos. A table
    whose default is empty ({}, such as fw.zones) holds names the user picks;
    the tool that reads it checks what's inside."""
    found = []
    for key, val in data.items():
        if key not in defaults:
            found.append(prefix + key)
        elif isinstance(val, dict) and isinstance(defaults[key], dict) and defaults[key]:
            found += unknown_keys(val, defaults[key], f"{prefix}{key}.")
    return found
