"""A change that undoes itself unless confirmed, for hb fw and hb ssh.

begin() saves the files a change will touch and starts a transient systemd
timer that runs `hb <tool> revert --timer`; only then does the tool write
anything. confirm() stops the timer. restore() puts the saved files back
(deleting the ones that didn't exist before); reloading the service is the
tool's job. The state sits in /var/lib/hb/<tool>/pending.json.
"""
import os
import shutil
import time

from . import util


class Guard:
    def __init__(self, tool):
        self.tool = tool
        self.unit = f"hb-{tool}-revert"

    @property
    def path(self):
        return os.path.join(util.state_dir(self.tool), "pending.json")

    def pending(self):
        """The waiting change, or None."""
        return util.read_json(self.path, None) if os.path.exists(self.path) else None

    def begin(self, paths, minutes, description, **extra):
        """Save paths, start the timer, record the change; (pending, None) or (None, error)."""
        run_id = os.environ.get("HB_RUN") or time.strftime("%Y%m%d-%H%M%S")
        backup = os.path.join(util.STATE, "backup", run_id)
        files = {}
        for path in paths:
            files[path] = None
            if os.path.exists(path):
                files[path] = backup + path
                os.makedirs(os.path.dirname(files[path]), mode=0o700, exist_ok=True)
                shutil.copy2(path, files[path])
        util.run("systemctl", "reset-failed", f"{self.unit}.timer", f"{self.unit}.service")
        rc, _, err = util.run("systemd-run", f"--unit={self.unit}", f"--on-active={minutes}min",
                              "--timer-property=AccuracySec=1s", f"--description=hb {self.tool}: {description}",
                              util.HB, self.tool, "revert", "--timer")
        if rc != 0:
            return None, f"cannot start the revert timer ({err.strip()})"
        pend = {"run": run_id, "files": files, "until": time.time() + minutes * 60, **extra}
        util.write_json(self.path, pend)
        return pend, None

    def stop_timer(self):
        """(ok, error text)."""
        rc, _, err = util.run("systemctl", "stop", f"{self.unit}.timer")
        return rc == 0, err.strip()

    def confirm(self):
        """Stop the timer and forget the change: (pending, None), (None, None) or (None, error)."""
        pend = self.pending()
        if pend is None:
            return None, None
        ok, err = self.stop_timer()
        if not ok:
            return None, f"could not stop the revert timer: {err}"
        os.unlink(self.path)
        return pend, None

    def restore(self, pend):
        """Put the saved files back and forget the change."""
        for path, saved in pend["files"].items():
            if saved:
                shutil.copy2(saved, path)
            elif os.path.exists(path):
                os.unlink(path)
        if os.path.exists(self.path):
            os.unlink(self.path)


def until_text(pend):
    return time.strftime("%H:%M", time.localtime(pend["until"]))
