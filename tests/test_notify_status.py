"""hb-notify (SMS dedupe, daily cap, retries) and hb-status (when to notify, banner)."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state, util  # noqa: E402

notify = load_tool("notify")
status = load_tool("status")


def cfg(**over):
    c = {"sms_command": [], "sms_per_day": 5, "repeat_hours": 24, "retry_minutes": 60}
    c.update(over)
    return c


class NotifyTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.p = notify.paths()
        self.outfile = os.path.join(util.STATE, "sms.txt")
        self.sender = ["sh", "-c", f"cat >> {self.outfile}"]

    def sent_lines(self):
        try:
            with open(self.outfile) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def test_sms_text_is_short_ascii(self):
        t = notify.sms_text("fail", "health.raid", "degraded: md2 – ó " + "x" * 300)
        self.assertLessEqual(len(t), 160)
        self.assertTrue(t.isascii())
        self.assertIn("FAIL health.raid: degraded: md2", t)
        self.assertTrue(t.endswith("..."))

    def test_same_key_once_per_repeat_window(self):
        c = cfg(sms_command=self.sender)
        self.assertTrue(notify.queue(self.p, c, "health.raid", "a"))
        self.assertFalse(notify.queue(self.p, c, "health.raid", "b"))  # already queued
        self.assertEqual(notify.flush(self.p, c), 1)
        self.assertFalse(notify.queue(self.p, c, "health.raid", "c"))  # sent recently
        self.assertTrue(notify.queue(self.p, c, "health.disk", "d"))   # another key
        self.assertTrue(notify.queue(self.p, c, "health.raid", "e", force=True))

    def test_daily_cap_drops_and_records(self):
        c = cfg(sms_command=self.sender, sms_per_day=2)
        for k in ("a", "b", "c"):
            notify.queue(self.p, c, k, f"text {k}")
        self.assertEqual(notify.flush(self.p, c), 2)
        self.assertEqual(self.sent_lines(), ["text a", "text b"])
        self.assertEqual(util.read_json(self.p["outbox"], None), [])
        self.assertIn("2 already sent in 24 h", util.read_events()[-1]["text"])

    def test_failed_send_is_retried_then_given_up(self):
        c = cfg(sms_command=["sh", "-c", "echo gateway down >&2; exit 3"])
        notify.queue(self.p, c, "k", "text")
        self.assertEqual(notify.flush(self.p, c), 0)
        box = util.read_json(self.p["outbox"], [])
        self.assertEqual((box[0]["tries"], box[0]["error"]), (1, "gateway down"))
        box[0]["ts"] -= 61 * 60
        util.write_json(self.p["outbox"], box)
        notify.flush(self.p, c)
        self.assertEqual(util.read_json(self.p["outbox"], None), [])
        self.assertIn("gave up on the SMS for k after 1 tries", util.read_events()[-1]["text"])

    def test_send_records_every_level_and_texts_only_fail(self):
        notify.refresh_banner = lambda: None
        c = cfg(sms_command=self.sender)
        notify.cmd_send(c, "warn", "backup", "last good backup 30 h ago")
        notify.cmd_send(c, "fail", "mdadm.Fail", "Fail on /dev/md2")
        self.assertEqual([e["level"] for e in util.read_events()], ["warn", "fail"])
        self.assertEqual(len(self.sent_lines()), 1)
        self.assertIn("FAIL mdadm.Fail: Fail on /dev/md2", self.sent_lines()[0])

    def test_events_are_trimmed(self):
        for i in range(notify.KEEP_EVENTS + 20):
            notify.record("info", "k", str(i))
        ev = util.read_events()
        self.assertEqual(len(ev), notify.KEEP_EVENTS)
        self.assertEqual(ev[-1]["text"], str(notify.KEEP_EVENTS + 19))


class StatusTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.calls = []
        self.results = {}
        status.collect = lambda: dict(self.results)
        status.notify = lambda level, key, text: self.calls.append((level, key))
        status.BANNER = os.path.join(util.STATE, "motd")
        self.real_run = util.run
        util.run = lambda *a, **k: (0, "", "")
        self.addCleanup(setattr, util, "run", self.real_run)

    def step(self, **levels):
        self.results = {k.replace("_", "."): (v, f"{k} detail") for k, v in levels.items()}
        self.calls.clear()
        status.refresh()
        return list(self.calls)

    def test_fail_notifies_on_the_second_refresh_only(self):
        self.assertEqual(self.step(health_raid="ok"), [])
        self.assertEqual(self.step(health_raid="fail"), [])
        self.assertEqual(self.step(health_raid="fail"), [("fail", "health.raid")])
        self.assertEqual(self.step(health_raid="fail"), [])
        self.assertEqual(self.step(health_raid="ok"), [("info", "health.raid")])

    def test_warn_from_ok_and_recovery(self):
        self.assertEqual(self.step(backup="warn"), [("warn", "backup")])
        self.assertEqual(self.step(backup="warn"), [])
        self.assertEqual(self.step(backup="ok"), [("info", "backup")])
        self.assertEqual(self.step(backup="skip"), [])

    def test_a_fail_that_clears_before_the_second_look_says_nothing(self):
        self.step(k8s="ok")
        self.assertEqual(self.step(k8s="fail"), [])
        self.assertEqual(self.step(k8s="ok"), [("info", "k8s")])

    def test_banner_lists_problems_first_then_events(self):
        self.step(health_raid="fail", backup="warn", health_disk="ok", health_nvme="skip")
        with open(status.BANNER) as f:
            lines = f.read().splitlines()
        self.assertIn("2 of 3 need attention", lines[0])
        self.assertTrue(lines[1].strip().startswith("FAIL  health.raid"))
        self.assertTrue(lines[2].strip().startswith("WARN  backup"))

    def test_banner_all_ok_shows_backup_and_disk(self):
        cache = {"ts": int(time.time()), "checks": {
            "backup": {"level": "ok", "detail": "last backup 6 h ago"},
            "health.disk": {"level": "ok", "detail": "/ 41% used"},
            "health.nvme": {"level": "skip", "detail": "needs root"}}}
        events = [{"ts": int(time.time()) - 60, "level": "fail", "key": "mdadm.Fail", "text": "Fail on /dev/md2"},
                  {"ts": int(time.time()) - 10 * 86400, "level": "info", "key": "old", "text": "too old"}]
        text = status.render(cache, events)
        self.assertIn("all 2 checks ok · last backup 6 h ago · / 41% used", text)
        self.assertIn("mdadm.Fail: Fail on /dev/md2", text)
        self.assertNotIn("too old", text)

    def test_strip_word(self):
        self.assertEqual(status.strip_word("ok: last backup 6 h ago"), "last backup 6 h ago")
        self.assertEqual(status.strip_word("warn: pending code"), "pending code")
        self.assertEqual(status.strip_word("ok"), "")


if __name__ == "__main__":
    unittest.main()
