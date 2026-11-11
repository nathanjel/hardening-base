"""The kubelet's memory settings for hb-k8s (items memory and memory_live): how much it keeps
for the system (--system-reserved=memory=...) and how little free memory makes it evict pods
(--eviction-hard="memory.available<..."), in microk8s's args file for the kubelet.

The flags are read as the kubelet reads them: the first line of a flag replaces what a config
file or the defaults set, later lines merge into it key by key (the last value of a key wins),
and an empty value ("") is an explicit empty setting. Only the memory parts change. Where the args
file has no such flag yet, hb starts it from what the kubelet runs now (its configz: a config
file's values or the defaults), so the other resources and signals stay as they are.

  kubelet.py check ARGS RESERVED EVICT MEMINFO CGROUP [REQUESTS]
        exit 0: the args file has it; 1: it would change (and what pods here ask for and use
        still fits); 2: a value can't be read, or the change would leave pods here without room;
        3: it would change, and REQUESTS (bytes the pods on this node ask for) with the kubelet's
        configz on stdin are needed to say whether that fits
  kubelet.py write ARGS RESERVED EVICT     configz on stdin: write the change into ARGS (in place,
                                           same owner and mode)
  kubelet.py live RESERVED EVICT           configz on stdin: exit 0 if the kubelet runs with it,
                                           1 if not yet, 2 if configz can't be read
  kubelet.py restore ARGS RESERVED EVICT   configz on stdin: write the managed flags back as the
                                           kubelet ran them (when it doesn't start with hb's)
  kubelet.py requests                      pods JSON on stdin: bytes of memory they ask for

RESERVED or EVICT "" leaves that setting alone. Python 3.9 (AL2023's python3), stdlib only.
"""
import json
import math
import os
import re
import sys
import tempfile
from fractions import Fraction

# Kubernetes quantities: a decimal number with a binary or decimal SI suffix, or an exponent
QUANTITY = re.compile(r"([+-]?)([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E)|[eE]([+-]?[0-9]+))?")
SUFFIX = {"": 1, "n": Fraction(1, 10**9), "u": Fraction(1, 10**6), "m": Fraction(1, 1000),
          "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18,
          "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60}
FLAGS = {"system-reserved": ("=", "systemReserved"), "kube-reserved": ("=", "kubeReserved"),
         "eviction-hard": ("<", "evictionHard")}
FLAG = re.compile(r"--(system-reserved|kube-reserved|eviction-hard)=(.*)")


def size(text, total=None):
    """Bytes in a Kubernetes quantity ("2Gi", "200M", "7e9", "1500m", rounded up), or a share of
    TOTAL ("5%") when TOTAL is given; None when it's neither, or negative."""
    t = (text or "").strip()
    m = QUANTITY.fullmatch(t)
    if m:
        sign, number, suffix, exp = m.groups()
        if sign == "-":
            return None
        scale = Fraction(10) ** int(exp) if exp is not None else SUFFIX[suffix or ""]
        return math.ceil(Fraction(number) * scale)
    m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)%", t)
    if m and total is not None and float(m.group(1)) <= 100:
        return math.ceil(Fraction(m.group(1)) / 100 * total)
    return None


def quantity(value, what):
    """size(value) for a value that must be a quantity when present: 0 when absent."""
    if value is None:
        return 0
    n = size(str(value))
    if n is None:
        raise ValueError(f"{what} {value!r} isn't a quantity hb can read")
    return n


def mib(n):
    return f"{n / 2**20:.0f} MiB"


def unquote(v):
    v = v.strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def parse_map(value, sep, what):
    """A map flag's value as the kubelet's parser reads it: comma-separated pairs, trimmed, empty
    pieces skipped, the last value of a key winning."""
    out = {}
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if sep not in piece:
            raise ValueError(f"{what} has a pair without '{sep}': {piece!r}")
        k, v = piece.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def flags(lines):
    """{flag: merged map} for the three map flags present in LINES (an explicit "" gives {})."""
    out = {}
    for line in lines:
        m = FLAG.fullmatch(line.strip())
        if m:
            name = m.group(1)
            out.setdefault(name, {}).update(parse_map(unquote(m.group(2)), FLAGS[name][0], f"--{name}"))
    return out


def current_maps(configz_text):
    """{flag: map} as the kubelet runs it now, from its configz."""
    c = json.loads(configz_text)["kubeletconfig"]
    return {name: dict(c.get(key) or {}) for name, (_, key) in FLAGS.items()}


def wanted(file, current, reserved, evict):
    """{flag: map} hb writes: each managed flag's map (the args file's, or what the kubelet runs
    when the file has none) with the memory part set."""
    out = {}
    for name, key, value in (("system-reserved", "memory", reserved), ("eviction-hard", "memory.available", evict)):
        if value:
            out[name] = dict(file[name] if name in file else current[name])
            out[name][key] = value
    return out


def same_value(have, want):
    """Whether a setting HAVE is the value WANT, by one rule for the args file and configz alike: a
    share matches a share of the same number (5% and 5.0%), a size a size of the same bytes (2Gi and
    2048Mi); a share never matches a size, whatever the machine's memory."""
    if have is None:
        return False
    have, want = have.strip(), want.strip()
    share = re.compile(r"([0-9]+(?:\.[0-9]+)?)%")
    a, b = share.fullmatch(have), share.fullmatch(want)
    if a or b:
        return bool(a and b) and Fraction(a.group(1)) == Fraction(b.group(1))
    x, y = size(have), size(want)
    return x is not None and x == y


def has_it(file, reserved, evict):
    return (not reserved or same_value(file.get("system-reserved", {}).get("memory"), reserved)) and \
        (not evict or same_value(file.get("eviction-hard", {}).get("memory.available"), evict))


def render(lines, values):
    """LINES with each flag in VALUES ({flag: map}) written as one line, in place of its first
    line (later lines of it dropped), or appended. An empty map is written as an explicit ""."""
    out, done = [], set()
    for line in lines:
        m = FLAG.fullmatch(line.strip())
        if m and m.group(1) in values:
            if m.group(1) not in done:
                out.append(line_for(m.group(1), values[m.group(1)]))
                done.add(m.group(1))
            continue
        out.append(line)
    out += [line_for(name, value) for name, value in values.items() if name not in done]
    return out


def line_for(name, mapping):
    sep = FLAGS[name][0]
    text = ",".join(k + sep + v for k, v in mapping.items())
    # quoted as microk8s writes --eviction-hard: its '<' must reach the kubelet as it is
    return f'--{name}="{text}"' if name == "eviction-hard" or not text else f"--{name}={text}"


def read_lines(path):
    with open(path) as f:
        return f.read().splitlines()


def write_lines(path, lines):
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".hb-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def mem_total(meminfo):
    with open(meminfo) as f:
        for line in f:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    raise ValueError("no MemTotal")


def pods_working_set(cgroup):
    """What the pods' cgroup holds less the files it could drop (the kubelet's working set)."""
    with open(os.path.join(cgroup, "kubepods", "memory.current")) as f:
        current = int(f.read())
    inactive = 0
    with open(os.path.join(cgroup, "kubepods", "memory.stat")) as f:
        for line in f:
            k, _, v = line.partition(" ")
            if k == "inactive_file":
                inactive = int(v)
    return max(current - inactive, 0)


def read_file(args):
    lines = read_lines(args)
    for line in lines:
        if re.match(r"\s*--(system-reserved|kube-reserved|eviction-hard)\s", line):
            raise ValueError(f"{args} has {line.split()[0]} with a space, not '=': hb doesn't edit that form")
    return lines, flags(lines)


def check(args, reserved, evict, meminfo, cgroup, requests=None, configz_text=None):
    """(exit code, message) for the memory item."""
    total = mem_total(meminfo)
    if reserved and size(reserved) is None:
        return 2, f"k8s.memory_reserved {reserved!r} isn't a size (like 2Gi)"
    if evict and size(evict, total) is None:
        return 2, f"k8s.memory_evict_below {evict!r} isn't a size (like 200Mi) or a share (like 5%)"
    try:
        lines, file = read_file(args)
    except ValueError as e:
        return 2, str(e)
    said = " and ".join(([f"keeps {reserved} for the system"] if reserved else []) +
                        ([f"evicts pods when less than {evict} is free"] if evict else []))
    if has_it(file, reserved, evict):
        return 0, f"the kubelet's args file {said}"
    if requests is None or configz_text is None:
        return 3, "needs what the pods here ask for and the kubelet's configz"
    try:
        current = current_maps(configz_text)
    except (ValueError, KeyError, TypeError) as e:
        return 2, f"the kubelet's configz can't be read: {e}"
    want = wanted(file, current, reserved, evict)
    after = {name: want.get(name, file.get(name, current[name])) for name in FLAGS}
    try:
        keep = quantity(after["system-reserved"].get("memory"), "system-reserved memory") + \
            quantity(after["kube-reserved"].get("memory"), "kube-reserved memory")
        threshold = after["eviction-hard"].get("memory.available")
        floor = 0 if threshold is None else size(threshold, total)
        if floor is None:
            raise ValueError(f"memory.available {threshold!r} isn't a size or a share")
    except ValueError as e:
        return 2, f"the kubelet's settings: {e}"
    allocatable, cap = total - keep - floor, total - keep
    kube = after["kube-reserved"].get("memory")
    if allocatable <= 0:
        return 2, f"keeping {mib(keep + floor)} back is all of this machine's {mib(total)}"
    try:
        used = pods_working_set(cgroup)
    except (OSError, ValueError) as e:
        return 2, f"can't read what the pods use (the kubepods cgroup): {e}"
    then = f"pods may then ask for {mib(allocatable)}" + (f" ({kube} is kept for Kubernetes too)" if kube else "")
    if requests > allocatable:
        return 2, f"{then}, but those running here already ask for {mib(requests)}: the kubelet would turn some of them away when it restarts"
    if used >= allocatable:
        return 2, f"{then}, but those running here already use {mib(used)}: the kubelet would start evicting them at once"
    change = []
    if reserved:
        change.append(f"system memory kept {current_or_file(file, current, 'system-reserved', 'memory') or 'none'} → {reserved}")
    if evict:
        change.append(f"evict below {current_or_file(file, current, 'eviction-hard', 'memory.available') or 'never'} → {evict}")
    return 1, (f"{'; '.join(change)} (args file): {then} "
               f"(they ask for {mib(requests)} and use {mib(used)}; the pods' cgroup is capped at {mib(cap)})")


def current_or_file(file, current, name, key):
    return (file[name] if name in file else current[name]).get(key)


def live(text, reserved, evict):
    """(exit code, message) for memory_live, from the kubelet's configz."""
    try:
        c = json.loads(text)["kubeletconfig"]
    except (ValueError, KeyError, TypeError) as e:
        return 2, f"the kubelet's configz can't be read: {e}"
    have_r = (c.get("systemReserved") or {}).get("memory")
    have_e = (c.get("evictionHard") or {}).get("memory.available")
    ok = (not reserved or same_value(have_r, reserved)) and (not evict or same_value(have_e, evict))
    runs = f"the kubelet runs keeping {have_r or 'nothing'} for the system and evicting below {have_e or 'nothing'}"
    return (0, runs) if ok else (1, f"{runs}; it loads the args file when kubelite restarts")


def restore(args, reserved, evict, configz_text):
    """Write the managed flags as the kubelet ran them (an empty map as an explicit "")."""
    current = current_maps(configz_text)
    values = {name: current[name] for name, managed in (("system-reserved", reserved), ("eviction-hard", evict)) if managed}
    write_lines(args, render(read_lines(args), values))


def pod_request(pod):
    """Bytes of memory one pod asks for, as the kubelet counts it when it admits the pod: the larger
    of its containers with every sidecar (an init container with restartPolicy Always keeps running)
    and each other init container with the sidecars started before it; with a pod-level request,
    the larger of that and the containers' count; plus the pod's overhead. During an in-place
    resize, the larger of what a container asks for and what the kubelet has allocated to it (what
    it admits on a restart)."""
    spec, status = pod.get("spec") or {}, pod.get("status") or {}
    meta = pod.get("metadata") or {}
    who = f"pod {meta.get('namespace', '?')}/{meta.get('name', '?')}"

    def requested(res):
        return ((res or {}).get("requests") or {}).get("memory")
    allocated = {}
    for s in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        allocated[s.get("name")] = max(quantity((s.get("allocatedResources") or {}).get("memory"), f"{who} allocated memory"),
                                       quantity(requested(s.get("resources")), f"{who} memory"))

    def req(c):
        return max(quantity(requested(c.get("resources")), f"{who} container {c.get('name')} memory request"),
                   allocated.get(c.get("name"), 0))
    sidecars, init = 0, 0
    for c in spec.get("initContainers") or []:
        if c.get("restartPolicy") == "Always":
            sidecars += req(c)
        else:
            init = max(init, req(c) + sidecars)
    base = max(sum(req(c) for c in spec.get("containers") or []) + sidecars, init)
    pod_level = requested(spec.get("resources"))
    if pod_level is not None:
        # never below the containers' own count: validation keeps a pod-level request at least their
        # sum, and a resize adding one keeps the containers' old allocation until the kubelet takes it
        base = max(base, quantity(pod_level, f"{who} pod-level memory request"),
                   quantity((status.get("allocatedResources") or {}).get("memory"), f"{who} allocated memory"))
    return base + quantity((spec.get("overhead") or {}).get("memory"), f"{who} overhead")


def pod_requests(pods):
    """Bytes of memory the pods that haven't finished ask for."""
    return sum(pod_request(p) for p in pods.get("items", [])
               if (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed"))


def main(argv):
    cmd, rest = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    # RESERVED and EVICT: written as given, so surrounding spaces go first (kubelite splits an
    # args-file line at spaces: "memory= 2Gi " would reach the kubelet as two arguments)
    where = {"check": (1, 2), "write": (1, 2), "live": (0, 1), "restore": (1, 2)}.get(cmd, ())
    rest = [v.strip() if i in where else v for i, v in enumerate(rest)]
    try:
        if cmd == "check" and len(rest) in (5, 6):
            if len(rest) == 6:
                rc, msg = check(*rest[:5], int(rest[5]), sys.stdin.read())
            else:
                rc, msg = check(*rest)
            print(msg)
            return rc
        if cmd == "write" and len(rest) == 3:
            args, reserved, evict = rest
            lines, file = read_file(args)
            write_lines(args, render(lines, wanted(file, current_maps(sys.stdin.read()), reserved, evict)))
            return 0
        if cmd == "live" and len(rest) == 2:
            rc, msg = live(sys.stdin.read(), *rest)
            print(msg)
            return rc
        if cmd == "restore" and len(rest) == 3:
            restore(*rest, sys.stdin.read())
            return 0
        if cmd == "requests" and not rest:
            print(pod_requests(json.load(sys.stdin)))
            return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"{cmd}: {e}")
        return 2
    print(__doc__.strip().split("\n\n")[2], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
