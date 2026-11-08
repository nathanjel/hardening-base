"""hb-health's k8s check on pod lists shaped like kubectl's JSON (evicted records, crash loops, jobs)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

health = load_tool("health")


def pod(ns, name, phase, ready=None, reason=None, waiting=None, containers=1):
    st = {"phase": phase}
    if reason:
        st["reason"] = reason
    if ready is not None:
        st["containerStatuses"] = [{"ready": i < ready, "state": {"waiting": {"reason": waiting}} if waiting and i >= ready
                                    else {"running": {}}} for i in range(containers)]
    return {"metadata": {"namespace": ns, "name": name}, "status": st,
            "spec": {"containers": [{}] * containers}}


RUNNING = [pod("scriba", "postgres-1", "Running", 1), pod("default", "mowapsa-a", "Running", 2, containers=2)]
JOB = pod("scriba", "db-backup-1", "Succeeded", 0)
# what the kubelet left on 5 Nov at 23:38: phase Failed, reason Evicted, the container record gone
EVICTED = [pod("default", f"mowapsa-old{i}", "Failed", reason="Evicted") for i in range(8)]


class K8sCheckTest(unittest.TestCase):
    def check(self, pods):
        old = health.run
        self.addCleanup(setattr, health, "run", old)
        health.run = lambda *cmd, timeout=30: ((0, "node1 Ready <none> 154d v1.35.6\n") if "nodes" in cmd
                                               else (0, json.dumps({"items": pods})))
        old_exists = health.os.path.exists
        self.addCleanup(setattr, health.os.path, "exists", old_exists)
        health.os.path.exists = lambda p: True if p == health.KUBECTL[0] else old_exists(p)
        return health.check_k8s({})

    def test_all_fine(self):
        self.assertEqual(self.check(RUNNING + [JOB]), (health.OK, "node Ready, 2 pods fine"))

    def test_evicted_records_with_their_replacements_running_are_a_warning(self):
        level, text = self.check(RUNNING + [JOB] + EVICTED)
        self.assertEqual(level, health.WARN)
        self.assertIn("8 evicted pods left over", text)
        self.assertIn("--field-selector=status.phase=Failed", text)

    def test_a_pod_that_is_down_still_fails(self):
        down = [pod("scriba", "web-1", "Running", 0, waiting="CrashLoopBackOff"),
                pod("scriba", "sms-1", "Pending")]
        level, text = self.check(RUNNING + down + EVICTED[:1])
        self.assertEqual(level, health.FAIL)
        self.assertIn("scriba/web-1 CrashLoopBackOff 0/1", text)
        self.assertIn("scriba/sms-1 Pending 0/1", text)
        self.assertIn("1 evicted pods left over", text)

    def test_a_failed_pod_that_was_not_evicted_fails(self):
        level, text = self.check(RUNNING + [pod("default", "x", "Failed", reason="OOMKilled")])
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/x OOMKilled", text)

    def test_unreadable_list_fails(self):
        old = health.run
        self.addCleanup(setattr, health, "run", old)
        health.run = lambda *cmd, timeout=30: (0, "node1 Ready x y z\n") if "nodes" in cmd else (0, "not json")
        self.assertEqual(health.check_k8s({})[0], health.FAIL)


if __name__ == "__main__":
    unittest.main()
