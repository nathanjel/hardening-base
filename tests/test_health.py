"""hb-health's k8s check on pod and controller lists shaped like kubectl's JSON."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

health = load_tool("health")


def ref(kind, uid, name=None):
    return [{"kind": kind, "uid": uid, "name": name or uid, "controller": True}]


def pod(ns, name, phase, ready=None, reason=None, waiting=None, containers=1, owner=None):
    st = {"phase": phase}
    if reason:
        st["reason"] = reason
    if ready is not None:
        st["containerStatuses"] = [{"ready": i < ready, "state": {"waiting": {"reason": waiting}} if waiting and i >= ready
                                    else {"running": {}}} for i in range(containers)]
    meta = {"namespace": ns, "name": name}
    if owner:
        meta["ownerReferences"] = ref(*owner)
    return {"metadata": meta, "status": st, "spec": {"containers": [{}] * containers}}


def evicted(name, owner=None):
    """What the kubelet left on 5 Nov at 23:38: phase Failed, reason Evicted, the container record gone."""
    return pod("default", name, "Failed", reason="Evicted", owner=owner)


def ctl(kind, uid, spec=None, status=None, owner=None):
    meta = {"uid": uid, "name": uid}
    if owner:
        meta["ownerReferences"] = ref(*owner)
    return {"kind": kind, "metadata": meta, "spec": spec or {}, "status": status or {}}


# 8 Nov: a Deployment of 2 whose two evicted pods were replaced by its ReplicaSet
MOWAPSA = [ctl("Deployment", "dep-mowapsa", {"replicas": 2}, {"availableReplicas": 2}),
           ctl("ReplicaSet", "rs-mowapsa", {"replicas": 2}, {"availableReplicas": 2},
               owner=("Deployment", "dep-mowapsa"))]
RUNNING = [pod("default", f"mowapsa-new{i}", "Running", 1, owner=("ReplicaSet", "rs-mowapsa")) for i in range(2)]


class K8sCheckTest(unittest.TestCase):
    def check(self, pods, controllers=(), readable=True):
        old = health.run
        self.addCleanup(setattr, health, "run", old)

        def run(*cmd, timeout=30):
            if "nodes" in cmd:
                return 0, "node1 Ready <none> 154d v1.35.6\n"
            if health.CONTROLLERS in cmd:
                return (0, json.dumps({"items": list(controllers)})) if readable else (1, "")
            return 0, json.dumps({"items": pods})
        health.run = run
        old_exists = health.os.path.exists
        self.addCleanup(setattr, health.os.path, "exists", old_exists)
        health.os.path.exists = lambda p: True if p == health.KUBECTL[0] else old_exists(p)
        return health.check_k8s({})

    def test_all_fine(self):
        self.assertEqual(self.check(RUNNING + [pod("scriba", "backup-1", "Succeeded", 0)]),
                         (health.OK, "node Ready, 2 pods fine"))

    def test_evictions_whose_controller_is_whole_again_are_a_warning(self):
        old = [evicted(f"mowapsa-old{i}", ("ReplicaSet", "rs-mowapsa")) for i in range(2)]
        level, text = self.check(RUNNING + old, MOWAPSA)
        self.assertEqual(level, health.WARN, text)
        self.assertIn("2 evicted pods left over", text)
        self.assertIn("--field-selector=status.phase=Failed", text)

    def test_a_surviving_sibling_is_not_a_replacement(self):
        # a StatefulSet of 2: db-0 is up, db-1 was evicted and nothing brought it back
        sts = [ctl("StatefulSet", "sts-db", {"replicas": 2}, {"availableReplicas": 1, "readyReplicas": 1})]
        level, text = self.check([pod("default", "db-0", "Running", 1, owner=("StatefulSet", "sts-db")),
                                  evicted("db-1", ("StatefulSet", "sts-db"))], sts)
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/db-1 Evicted, StatefulSet sts-db has 1 of 2 available", text)

    def test_a_replicaset_short_of_its_count_fails_even_with_siblings_up(self):
        rs = [ctl("ReplicaSet", "rs-web", {"replicas": 3}, {"availableReplicas": 2})]
        pods = [pod("default", f"web-{i}", "Running", 1, owner=("ReplicaSet", "rs-web")) for i in range(2)]
        level, text = self.check(pods + [evicted("web-old", ("ReplicaSet", "rs-web"))], rs)
        self.assertEqual(level, health.FAIL)
        self.assertIn("ReplicaSet rs-web has 2 of 3 available", text)

    def test_a_rollout_since_is_judged_by_the_deployment(self):
        sets = [ctl("Deployment", "dep-web", {"replicas": 1}, {"availableReplicas": 1}),
                ctl("ReplicaSet", "rs-web-1", {"replicas": 0}, {}, owner=("Deployment", "dep-web")),
                ctl("ReplicaSet", "rs-web-2", {"replicas": 1}, {"availableReplicas": 1}, owner=("Deployment", "dep-web"))]
        new = pod("default", "web-new", "Running", 1, owner=("ReplicaSet", "rs-web-2"))
        self.assertEqual(self.check([new, evicted("web-old", ("ReplicaSet", "rs-web-1"))], sets)[0], health.WARN)
        sets[0]["status"]["availableReplicas"] = 0
        self.assertEqual(self.check([evicted("web-old", ("ReplicaSet", "rs-web-1"))], sets)[0], health.FAIL)

    def test_daemonsets_and_jobs(self):
        ds = [ctl("DaemonSet", "ds-calico", {}, {"desiredNumberScheduled": 1, "numberAvailable": 1})]
        self.assertEqual(self.check([evicted("calico-old", ("DaemonSet", "ds-calico"))], ds)[0], health.WARN)
        done = [ctl("Job", "job-backup", {"completions": 1}, {"succeeded": 1})]
        self.assertEqual(self.check([evicted("backup-old", ("Job", "job-backup"))], done)[0], health.WARN)
        running = [ctl("Job", "job-backup", {"completions": 1}, {"active": 1})]
        level, text = self.check([evicted("backup-old", ("Job", "job-backup"))], running)
        self.assertEqual(level, health.FAIL)
        self.assertIn("Job job-backup has 0 of 1 available", text)

    def test_a_lone_evicted_pod_is_a_failure(self):
        level, text = self.check([evicted("standalone")])
        self.assertEqual(level, health.FAIL)
        self.assertEqual(text, "default/standalone Evicted, and no controller to replace it")

    def test_unknown_or_unreadable_controllers_fail(self):
        level, text = self.check([evicted("x", ("ReplicaSet", "rs-gone"))], MOWAPSA)
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/x Evicted, and its ReplicaSet rs-gone is gone", text)
        level, text = self.check(RUNNING + [evicted("y", ("ReplicaSet", "rs-mowapsa"))], MOWAPSA, readable=False)
        self.assertEqual(level, health.FAIL)
        self.assertIn("default/y Evicted, and its controller couldn't be read", text)

    def test_a_pod_that_is_down_still_fails(self):
        down = [pod("scriba", "web-1", "Running", 0, waiting="CrashLoopBackOff"),
                pod("scriba", "sms-1", "Pending")]
        level, text = self.check(RUNNING + down + [evicted("mowapsa-old", ("ReplicaSet", "rs-mowapsa"))], MOWAPSA)
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



class RebootCheckTest(unittest.TestCase):
    def check(self, nr, rpm_rc=0, kernel=None):
        running = os.uname().release
        old = health.run
        self.addCleanup(setattr, health, "run", old)

        def run(*cmd, timeout=30):
            if cmd[0] == "rpm":
                return rpm_rc, f"1700000000 {kernel or running}\n" if rpm_rc == 0 else ""
            return nr, ""
        health.run = run
        return health.check_reboot({"reboot_fail_days": 7})

    def test_answers(self):
        self.assertEqual(self.check(0)[0], health.OK)
        self.assertEqual(self.check(1), (health.WARN, "updated system libraries need a reboot"))
        self.assertEqual(self.check(0, kernel="9.9.9-1.fc44.x86_64")[0], health.FAIL)   # waited long enough

    def test_no_answer_is_not_ok(self):
        for nr, text in ((2, "exit 2"), (127, "not installed"), (124, "timed out")):
            level, line = self.check(nr)
            self.assertEqual(level, health.WARN, nr)
            self.assertIn(f"can't tell whether a reboot is needed: dnf needs-restarting -r: {text}", line)
        level, line = self.check(0, rpm_rc=1)
        self.assertEqual(level, health.WARN)
        self.assertIn("rpm can't list kernel-core (exit 1)", line)

if __name__ == "__main__":
    unittest.main()
