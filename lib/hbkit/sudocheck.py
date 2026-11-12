"""Whether only root can change what sudo runs, for hb-harden's nopasswd and admins items.

root_only(PATH) walks PATH as the kernel resolves it, one component at a time, never resolving
it first: every folder on the way and the file itself must be root's, writable by no other group
or user (a world-writable folder passes only with its sticky bit, which keeps others from
replacing root's entries in it; a file never does), and have no access ACL (whose mask hides
named writers in the group bits). A symbolic link must be root's too (in a sticky folder its
owner could replace it); its target is spliced into the walk where the link was.

allowed_rule(RULE) takes the one form hb can check, USER HOST=(RUNAS) NOPASSWD: /full/path [args]
[, /full/path [args]]..., and returns the programs it runs and the files their arguments name;
aliases, ALL, other tags, negations, wildcards, folders (a trailing /), interpreters (a shell, env,
python...: they run whatever they are given) and any ':', '=' or '\\' among the commands
(another grant can start there) are refused, since what they allow can't be read from the rule.

  sudocheck.py root-only [--top DIR] PATH...   exit 0: only root can change them; 1: who else can
  sudocheck.py allowed [--top DIR] RULE        exit 0: the rule's form and its programs pass; 2: not

--top stops the walk at DIR (the tests' stand-in for /, as a user namespace shows folders above
it as nobody's). Python 3.9 (AL2023's python3), stdlib only.
"""
import grp
import os
import pwd
import re
import stat
import sys

MAX_LINKS = 40
# every field held to its own characters, so none can swallow another grant (a host of
# "ALL=(root)NOPASSWD:/x:ALL" would): a user or %group, a host, a run-as list, then the commands
RULE = re.compile(r"^(?P<user>%?[A-Za-z0-9_][A-Za-z0-9_.-]*)\s+(?P<host>[A-Za-z0-9_][A-Za-z0-9_.-]*)\s*=\s*"
                  r"(\((?P<runas>[A-Za-z0-9_.%,: -]*)\)\s*)?NOPASSWD:\s*(?P<cmds>.+)$")
COMMAND = re.compile(r"^(?P<path>/[^\s,]+)(\s+[^,]*)?$")
CLAUSE = re.compile(r"[:=\\]")      # a second host clause (:), a binding (=) or an escape (\) in the commands
WILDCARD = re.compile(r"[*?\[\]]")
# programs that run whatever they are given (a script, a command line, another program): an
# allowed rule should name the helper itself
INTERPRETER = re.compile(r"^(sh|bash|dash|zsh|ksh|csh|tcsh|fish|busybox|env|sudo|su|runuser|doas|nohup|setsid|nice|"
                         r"ionice|chroot|xargs|find|awk|gawk|sed|perl|ruby|lua|node|php|tclsh|expect|"
                         r"python[0-9.]*|pypy[0-9.]*)$")


def name_of(uid=None, gid=None):
    try:
        return pwd.getpwuid(uid).pw_name if uid is not None else grp.getgrgid(gid).gr_name
    except KeyError:
        return str(uid if uid is not None else gid)


def has_access_acl(path):
    try:
        return "system.posix_acl_access" in os.listxattr(path, follow_symlinks=False)
    except OSError:
        return False


def node_problems(path, st):
    out = []
    if st.st_uid != 0:
        out.append(f"{path} is {name_of(uid=st.st_uid)}'s")
    if st.st_mode & 0o002 and not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
        out.append(f"{path} can be written by anyone")
    if st.st_mode & 0o020 and st.st_gid != 0:
        out.append(f"{path} can be written by group {name_of(gid=st.st_gid)}")
    if has_access_acl(path):
        out.append(f"{path} has an access ACL (named users or groups may write to it)")
    return out


def root_only(path, top="/"):
    """[] when only root can change what PATH runs, else what lets someone else.

    The walk resolves PATH as the kernel does: component by component, a link's target spliced in
    where the link was (so a link inside a target is followed before a ".." after it), and ".."
    always the real parent of the folder reached so far, which holds no links."""
    if not path.startswith("/"):
        return [f"{path} isn't a full path"]
    top = top.rstrip("/") or "/"

    def inside(p):          # at or below top: judged (everything is, with the real top, /)
        return top == "/" or (p + "/").startswith(top + "/")

    out = node_problems("/", os.lstat("/")) if top == "/" else []
    queue, cur, links = [p for p in path.split("/") if p], "/", 0
    while queue:
        name = queue.pop(0)
        if name == ".":
            continue
        if name == "..":
            cur = os.path.dirname(cur)
            continue
        nxt = os.path.join(cur, name)
        if not inside(nxt) and not (top + "/").startswith(nxt + "/"):
            return out + [f"{path} leads outside {top} ({nxt})"]
        try:
            st = os.lstat(nxt)
        except OSError as e:
            return out + [f"{nxt}: {e.strerror.lower()}"]
        if stat.S_ISLNK(st.st_mode):
            links += 1
            if links > MAX_LINKS:
                return out + [f"{path}: too many symbolic links"]
            # a link is as safe as its folder, and as its owner: in a sticky folder the owner of an
            # entry may replace it
            if inside(nxt) and st.st_uid != 0:
                out.append(f"{nxt} (a link) is {name_of(uid=st.st_uid)}'s")
            target = os.readlink(nxt)
            if target.startswith("/"):
                cur = "/"
            queue = [p for p in target.split("/") if p] + queue
            continue
        if inside(nxt):
            out += node_problems(nxt, st)
        cur = nxt
    return out


def allowed_rule(rule):
    """([programs it runs], None), or (None, why hb can't check it)."""
    m = RULE.match(rule.strip())
    if not m:
        return None, ("hb checks allowed rules of one form only: USER HOST=(RUNAS) NOPASSWD: /full/path [args], ... "
                      f"(not {rule.strip()!r})")
    if CLAUSE.search(m.group("cmds")):
        return None, (f"{m.group('cmds').strip()!r} in an allowed rule holds ':', '=' or '\\', which can start another "
                      "grant or hide one; hb takes plain arguments only")
    paths = []
    for cmd in m.group("cmds").split(","):
        c = COMMAND.match(cmd.strip())
        if not c:
            return None, f"{cmd.strip()!r} in an allowed rule isn't a program's full path (an alias, ALL, a tag or a negation)"
        if WILDCARD.search(c.group("path")):
            return None, f"{c.group('path')!r} in an allowed rule is a pattern, not one program"
        if c.group("path").endswith("/"):
            return None, f"{c.group('path')!r} in an allowed rule is a folder: sudo would run anything in it"
        if INTERPRETER.match(os.path.basename(c.group("path"))):
            return None, (f"{c.group('path')!r} in an allowed rule runs whatever it is given (a script, a command): "
                          "allow the helper itself")
        paths.append(c.group("path"))
        # a file an argument names (a script, a config) is input the program acts on: root's too
        paths += [a for a in cmd.split()[1:] if a.startswith("/")]
    return paths, None


def main(argv):
    args, top = argv[2:], "/"
    if args[:1] == ["--top"] and len(args) >= 2:
        top, args = args[1], args[2:]
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "root-only" and args:
        problems = [p for a in args for p in root_only(a, top)]
        for p in problems:
            print(p)
        return 1 if problems else 0
    if cmd == "allowed" and len(args) == 1:
        paths, why = allowed_rule(args[0])
        if why:
            print(why)
            return 2
        problems = [p for a in paths for p in root_only(a, top)]
        for p in problems:
            print(f"{p}, and an allowed rule runs it")
        return 2 if problems else 0
    print(__doc__.strip().split("\n\n")[3], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
