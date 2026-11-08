"""hb-health's k8s check on pod lists shaped like kubectl's JSON (evicted records, crash loops, jobs)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

health = load_tool("health")


def pod(ns, name, phase, ready=None, reason=None, waiting=None, containers=1, owner=None):
    st = {"phase": phase}
    if reason:
        st["reason"] = reason
    if ready is not None:
        st["containerStatuses"] = [{"ready": i < ready, "state": {"waiting": {"reason": waiting}} if waiting and i >= ready
                                    else {"running": {}}} for i in range(containers)]
    meta = {"namespace": ns, "name": name}
    if owner:
        meta["ownerReferences"] = [{"kind": "ReplicaSet", "uid": owner, "controller": True}]
    return {"metadata": meta, "status": st, "spec": {"containers": [{}] * containers}}


def evicted(name, owner=None):
    """What the kubelet left on 5 Nov at 23:38: phase Failed, reason Evicted, the container record gone."""
    return pod("default", name, "Failed", reason="Evicted", owner=owner)


RUNNING = [pod("scriba", "postgres-1", "Running", 1, owner="rs-postgres"),
           pod("default", "mowapsa-new", "Running", 2, containers=2, owner="rs-mowapsa")]
JOB = pod("scriba", "db-backup-1", "Succeeded", 0, owner="job-backup")


class K8sCheckTest(unittest.TestCase):
    def check(self, pods, replicasets=()):
        old = health.run
        self.addCleanup(setattr, health, "run", old)

        def run(*cmd, timeout=30):
            if "nodes" in cmd:
                return 0, "node1 Ready <none> 154d v1.35.6\n"
            if "replicasets" in cmd:
                return 0, json.dumps({"items": list(replicasets)})
            return 0, json.dumps({"items": pods})
        health.run = run
        old_exists = health.os.path.exists
        self.addCleanup(setattr, health.os.path, "exists", old_exists)
        health.os.path.exists = lambda p: True if p == health.KUBECTL[0] else old_exists(p)
        return health.check_k8s({})

    def test_all_fine(self):
        self.assertEqual(self.check(RUNNING + [JOB]), (health.OK, "node Ready, 2 pods fine"))

    def test_evicted_records_whose_workload_runs_again_are_a_warning(self):
        level, text = self.check(RUNNING + [JOB] + [evicted(f"mowapsa-old{i}", "rs-mowapsa") for i in range(2)]
                                 + [evicted("backup-old", "job-backup")])
        self.assertEqual(level, health.WARN, text)
        self.assertIn("3 evicted pods left over", text)
        self.assertIn("--field-selector=status.phase=Failed", text)

    def test_a_lone_evicted_pod_is_a_failure(self):
        level, text = self.check([evicted("standalone")])
        self.assertEqual(level, health.FAIL)
        self.assertEqual(text, "default/standalone Evicted, and no controller to replace it")

    def test_an_evicted_pod_nothing_replaced_is_a_failure(self):
        level, text = self.check(RUNNING + [evicted("sms-old", "rs-sms")])
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/sms-old Evicted, nothing has replaced it", text)

    def test_a_rollout_since_counts_as_replaced(self):
        new = pod("default", "web-new", "Running", 1, owner="rs-web-2")
        sets = [{"metadata": {"uid": u, "ownerReferences": [{"kind": "Deployment", "uid": "dep-web", "controller": True}]}}
                for u in ("rs-web-1", "rs-web-2")]
        self.assertEqual(self.check([new, evicted("web-old", "rs-web-1")], sets)[0], health.WARN)
        self.assertEqual(self.check([new, evicted("web-old", "rs-web-1")])[0], health.FAIL)   # can't tell: fail

    def test_a_replacement_that_is_down_fails_both(self):
        down = pod("default", "sms-new", "Pending", owner="rs-sms")
        level, text = self.check([down, evicted("sms-old", "rs-sms")])
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/sms-new Pending 0/1", text)
        self.assertIn("default/sms-old Evicted, nothing has replaced it", text)

    def test_a_pod_that_is_down_still_fails(self):
        down = [pod("scriba", "web-1", "Running", 0, waiting="CrashLoopBackOff"),
                pod("scriba", "sms-1", "Pending")]
        level, text = self.check(RUNNING + down + [evicted("mowapsa-old", "rs-mowapsa")])
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
