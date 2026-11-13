"""sudo's PAM file for hb-harden's admins item: members of one group answer sudo with their code
(hb totp) instead of a password; everyone else goes on to the stack as before, and NOPASSWD rules
never reach it.

Two lines go in just before the file's one `auth include system-auth`:

  auth  [success=ignore auth_err=1 ignore=1 default=die]  pam_succeed_if.so quiet user ingroup GROUP
  auth  [success=done default=die]  pam_exec.so quiet expose_authtok VERIFIER verify

For a member, pam_succeed_if succeeds (ignore: go on) and the code decides: accepted ends the stack
(done), refused fails it at once (die), so a password never stands in for a wrong code. For anyone
else the condition is false (auth_err) and the code line is skipped. Any other answer (a service
error, say) fails the stack: it never downgrades a member to the password. sudo's pam_setcred runs
the stack again: pam_succeed_if answers "ignore" there for everyone, which also skips the code line,
so setcred is system-auth's, exactly as without these lines (on Fedora and AL2023 its pam_unix
lets it succeed). No other auth line (in any case: PAM reads AUTH as auth) or @include may come
before hb's: one could decide first (a "sufficient" password step, a jump). A file with a line that
PAM joins to the next one (its text before any '#' ends in a backslash) is refused: hb reads one
line at a time, and "auth\\" then "sufficient pam_permit.so" is an auth line it wouldn't see.

  sudopam.py check FILE GROUP VERIFIER   exit 0: in place; 1: would change; 2: refused (layout)
  sudopam.py write FILE GROUP VERIFIER   put the lines in (in place, same owner and mode)
  sudopam.py check-login FILE            exit 0 when sudo -i's service (sudo-i) reaches the gate:
                                         its only auth line is `auth include sudo`; 2 otherwise

Python 3.9 (AL2023's python3), stdlib only.
"""
import os
import re
import sys
import tempfile

NOTE = "# hb-harden: members of {group} answer with their code (hb totp); everyone else goes on as before"
NOTE_RE = re.compile(r"^#\s*hb-harden:")
INCLUDE_RE = re.compile(r"^auth\s+include\s+system-auth\s*$")
GROUP_LINE_RE = re.compile(r"^auth\s+\[success=ignore\s+auth_err=1\s+ignore=1\s+default=die\]\s+pam_succeed_if\.so\s+quiet"
                           r"\s+user\s+ingroup\s+(\S+)\s*$")
# PAM reads module types in any case, and its tokenizer drops brackets around a token: [auth] is auth
# (the token ends at the bracket: [auth]sufficient is two tokens), and a bracket starts a token
AUTH_RE = re.compile(r"^(\[-?auth\]|-?auth(\s|\[|$)|@include\b)", re.IGNORECASE)
CODE_LINE_RE = re.compile(r"^auth\s+\[success=done\s+default=die\]\s+pam_exec\.so\s+quiet\s+expose_authtok\s+(\S+/hb-totp)\s+verify\s*$")
GROUP_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def continued(lines):
    """The first line PAM goes on reading in the next (libpam cuts a comment at '#' first, so a
    comment never goes on), or None."""
    for line in lines:
        if line.split("#", 1)[0].rstrip().endswith("\\"):
            return line.strip()
    return None


def hb_lines(group, verifier):
    return [NOTE.format(group=group),
            f"auth       [success=ignore auth_err=1 ignore=1 default=die] pam_succeed_if.so quiet user ingroup {group}",
            f"auth       [success=done default=die] pam_exec.so quiet expose_authtok {verifier} verify"]


def want(text, group, verifier):
    """(the file with hb's lines in place, None), or (None, why it can't be changed)."""
    if not GROUP_NAME.match(group):
        return None, f"{group!r} isn't a group name"
    if not os.path.isabs(verifier) or not verifier.endswith("/hb-totp"):
        return None, f"{verifier!r} isn't hb-totp's full path"
    lines = text.splitlines()
    if continued(lines):
        return None, f"a line goes on in the next one (it ends in a backslash), which hb doesn't read: {continued(lines)!r}"
    kept = []
    for line in lines:
        s = line.strip()
        if NOTE_RE.match(s) or GROUP_LINE_RE.match(s) or CODE_LINE_RE.match(s):
            continue                              # hb's own lines, from before: written again below
        if "hb-totp" in s or ("pam_succeed_if" in s and "ingroup" in s and s.startswith("auth")):
            return None, f"a line that looks like hb's but isn't its own: {s!r} (edited by hand?)"
        kept.append(line)
    at = [i for i, line in enumerate(kept) if INCLUDE_RE.match(line.strip())]
    if len(at) != 1:
        return None, f"the file doesn't have exactly one 'auth include system-auth' line ({len(at)})"
    before = [line.strip() for line in kept[:at[0]] if AUTH_RE.match(line.strip())]
    if before:
        return None, f"an auth line comes before 'auth include system-auth' and could decide first: {before[0]!r}"
    out = kept[:at[0]] + hb_lines(group, verifier) + kept[at[0]:]
    return "\n".join(out) + "\n", None


LOGIN_INCLUDE_RE = re.compile(r"^auth\s+(include|substack)\s+sudo\s*$", re.IGNORECASE)


def check_login(path):
    """(exit code, message) for sudo -i's own service, which sudo picks for a login shell whatever
    the Defaults say: it reaches hb's gate only if all it does to authenticate is include sudo."""
    try:
        with open(path) as f:
            lines = [line.strip() for line in f.read().splitlines()]
    except OSError as e:
        return 2, f"can't read {path}, which sudo -i uses: {e}"
    if continued(lines):
        return 2, f"{path} (what sudo -i asks with) has a line that goes on in the next one, which hb doesn't read: {continued(lines)!r}"
    auth = [line for line in lines if AUTH_RE.match(line)]
    if len(auth) == 1 and LOGIN_INCLUDE_RE.match(auth[0]):
        return 0, f"{path}: sudo -i goes through sudo's gate"
    return 2, (f"{path} (what sudo -i asks with) authenticates other than by 'auth include sudo' alone, "
               f"past hb's gate: {auth[0] if auth else 'no auth line'!r}")


def check(path, group, verifier):
    """(exit code, message)."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        return 2, f"can't read {path}: {e}"
    new, why = want(text, group, verifier)
    if why:
        return 2, f"{path}: {why}"
    if new == text:
        return 0, f"{path}: {group}'s members answer with their code"
    return 1, f"{path}: sudo doesn't ask {group}'s members for their code yet"


def write(path, group, verifier):
    with open(path) as f:
        new, why = want(f.read(), group, verifier)
    if why:
        raise ValueError(why)
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".hb-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main(argv):
    if len(argv) == 5 and argv[1] == "check":
        rc, msg = check(*argv[2:])
        print(msg)
        return rc
    if len(argv) == 3 and argv[1] == "check-login":
        rc, msg = check_login(argv[2])
        print(msg)
        return rc
    if len(argv) == 5 and argv[1] == "write":
        try:
            write(*argv[2:])
        except (OSError, ValueError) as e:
            print(f"write: {e}")
            return 2
        return 0
    print(__doc__.strip().split("\n\n")[4], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
