"""hbkit.kubelet: the kubelet's memory flags in microk8s's args file, and whether pods still fit."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import tools  # noqa: E402,F401  (puts lib/ on the path)
from hbkit import kubelet  # noqa: E402

MICROK8S_ARGS = """--kubeconfig=${SNAP_DATA}/credentials/kubelet.config
--cert-dir=${SNAP_DATA}/certs
--fail-swap-on=false
--eviction-hard="memory.available<100Mi,nodefs.available<1Gi,imagefs.available<1Gi"
--container-runtime-endpoint=${SNAP_COMMON}/run/containerd.sock
"""
GI, MI = 2**30, 2**20
# the kubelet's Linux defaults (pkg/kubelet/eviction/defaults_linux.go), as configz shows them
DEFAULTS = {"imagefs.available": "15%", "imagefs.inodesFree": "5%", "memory.available": "100Mi",
            "nodefs.available": "10%", "nodefs.inodesFree": "5%"}


def configz(system=None, kube=None, evict=None):
    c = {"evictionHard": DEFAULTS if evict is None else evict}
    if system is not None:
        c["systemReserved"] = system
    if kube is not None:
        c["kubeReserved"] = kube
    return json.dumps({"kubeletconfig": c}, sort_keys=True)       # Go sorts a map's keys


def running(args_text):
    """configz for a kubelet started with ARGS_TEXT and no config file."""
    f = kubelet.flags(args_text.splitlines())
    return configz(f.get("system-reserved"), f.get("kube-reserved"), f.get("eviction-hard"))


class KubeletMemoryTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.args, self.meminfo, self.cg = f"{d}/kubelet", f"{d}/meminfo", f"{d}/cg"
        self.write_args(MICROK8S_ARGS)
        self.mem_total(8001176)
        os.makedirs(f"{self.cg}/kubepods")
        self.pods_use(4807 * MI, 691 * MI)

    def write_args(self, text):
        with open(self.args, "w") as f:
            f.write(text)
        os.chmod(self.args, 0o660)

    def mem_total(self, kib):
        with open(self.meminfo, "w") as f:
            f.write(f"MemTotal:       {kib} kB\nMemFree:          211000 kB\n")

    def pods_use(self, current, inactive):
        with open(f"{self.cg}/kubepods/memory.current", "w") as f:
            f.write(f"{current}\n")
        with open(f"{self.cg}/kubepods/memory.stat", "w") as f:
            f.write(f"anon 3000000000\nfile 1400000000\nactive_file 700000000\ninactive_file {inactive}\n")

    def check(self, reserved="2Gi", evict="200Mi", requests=None, z=None):
        if requests is not None and z is None:
            z = running(self.text())
        return kubelet.check(self.args, reserved, evict, self.meminfo, self.cg, requests, z)

    def write(self, reserved="2Gi", evict="200Mi", z=None):
        lines, file = kubelet.read_file(self.args)
        z = z or running(self.text())
        kubelet.write_lines(self.args, kubelet.render(lines, kubelet.wanted(file, kubelet.current_maps(z), reserved, evict)))

    def lines(self):
        return kubelet.read_lines(self.args)

    def text(self):
        with open(self.args) as f:
            return f.read()

    def test_sizes(self):
        for text, want in (("2Gi", 2 * GI), ("200Mi", 200 * MI), ("500M", 500 * 10**6), ("1.5Gi", int(1.5 * GI)),
                           ("1024", 1024), ("7e9", 7 * 10**9), ("7E9", 7 * 10**9), ("1E", 10**18), ("1Pi", 2**50),
                           ("1500m", 2), (".5Ki", 512), ("1.", 1), ("+1Ki", 1024), (" 2Gi ", 2 * GI)):
            self.assertEqual(kubelet.size(text), want, text)
        self.assertEqual(kubelet.size("5%", 1000), 50)
        for bad in ("", "2 Gi", "2gb", "-1Gi", "lots", "5%", "1e", "Gi"):
            self.assertIsNone(kubelet.size(bad), bad)
        self.assertIsNone(kubelet.size("101%", 1000))

    def test_pending_then_written_in_place(self):
        rc, msg = self.check()
        self.assertEqual(rc, 3)                        # needs the pods' requests and configz to judge
        rc, msg = self.check(requests=4022 * MI)
        self.assertEqual(rc, 1, msg)
        self.assertIn("system memory kept none → 2Gi; evict below 100Mi → 200Mi", msg)
        self.assertIn("pods may then ask for 5566 MiB", msg)       # 7814 - 2048 - 200
        self.assertIn("they ask for 4022 MiB and use 4116 MiB", msg)
        self.assertIn("capped at 5766 MiB", msg)
        z = running(MICROK8S_ARGS)
        self.write(z=z)
        self.assertEqual(self.lines(), [
            "--kubeconfig=${SNAP_DATA}/credentials/kubelet.config",
            "--cert-dir=${SNAP_DATA}/certs",
            "--fail-swap-on=false",
            '--eviction-hard="memory.available<200Mi,nodefs.available<1Gi,imagefs.available<1Gi"',
            "--container-runtime-endpoint=${SNAP_COMMON}/run/containerd.sock",
            "--system-reserved=memory=2Gi"])
        self.assertEqual(os.stat(self.args).st_mode & 0o777, 0o660)
        rc, msg = self.check()
        self.assertEqual(rc, 0, msg)
        self.assertEqual(msg, "the kubelet's args file keeps 2Gi for the system and evicts pods when less than 200Mi is free")
        before = self.lines()
        self.write(z=z)                                         # twice changes nothing
        self.assertEqual(self.lines(), before)

    def test_repeated_lines_merge_key_by_key(self):
        # Codex round 1: the kubelet merges repeated map flags; this reserves cpu and memory and
        # keeps both eviction signals
        self.write_args('--system-reserved=cpu=500m\n--system-reserved=memory=1Gi\n'
                        '--eviction-hard="nodefs.available<1Gi"\n--eviction-hard="memory.available<100Mi"\n--max-pods=110\n')
        self.write()
        self.assertEqual(self.lines(), ["--system-reserved=cpu=500m,memory=2Gi",
                                        '--eviction-hard="nodefs.available<1Gi,memory.available<200Mi"', "--max-pods=110"])
        # within one value the last of a key wins, and spaces around pairs don't count
        self.assertEqual(kubelet.parse_map(" memory=1Gi , cpu=1, memory=3Gi,", "=", "x"), {"memory": "3Gi", "cpu": "1"})

    def test_repeated_kube_reserved_counts(self):
        self.write_args(MICROK8S_ARGS + "--kube-reserved=cpu=100m\n--kube-reserved=memory=1Gi\n")
        rc, msg = self.check(requests=0)
        self.assertEqual(rc, 1, msg)
        self.assertIn("pods may then ask for 4542 MiB (1Gi is kept for Kubernetes too)", msg)   # 7814 - 2048 - 1024 - 200

    def test_a_config_files_settings_count_and_stay(self):
        # Codex round 1: kubeReserved 2Gi from a config file (not in the args file) leaves 3896 MiB
        self.mem_total(8 * GI // 1024)
        self.pods_use(2 * GI, 0)
        z = configz(system={"cpu": "250m"}, kube={"memory": "2Gi"}, evict={"memory.available": "100Mi", "nodefs.available": "5%"})
        self.write_args("--fail-swap-on=false\n")
        rc, msg = self.check(requests=5 * GI, z=z)
        self.assertEqual(rc, 2, msg)
        self.assertIn("pods may then ask for 3896 MiB", msg)
        self.assertEqual(self.check(requests=3 * GI, z=z)[0], 1)
        self.write(z=z)                                # flags start from what the kubelet runs
        self.assertEqual(self.lines(), ["--fail-swap-on=false", "--system-reserved=cpu=250m,memory=2Gi",
                                        '--eviction-hard="memory.available<200Mi,nodefs.available<5%"'])

    def test_the_default_threshold_counts_when_eviction_is_unmanaged(self):
        # Codex round 1: no --eviction-hard and only memory_reserved managed: the kubelet's 100Mi still applies
        self.mem_total(8 * GI // 1024)
        self.pods_use(2 * GI, 0)
        self.write_args("--fail-swap-on=false\n")
        rc, msg = self.check(evict="", requests=6100 * MI, z=configz())
        self.assertEqual(rc, 2, msg)
        self.assertIn("pods may then ask for 6044 MiB", msg)
        self.write(evict="", z=configz())
        self.assertEqual(self.lines(), ["--fail-swap-on=false", "--system-reserved=memory=2Gi"])

    def test_no_eviction_flag_starts_from_what_the_kubelet_runs(self):
        self.write_args("--fail-swap-on=false\n")
        self.write(reserved="", z=configz())
        flag = self.lines()[1]
        self.assertTrue(flag.startswith('--eviction-hard="'), flag)
        self.assertEqual(kubelet.flags(self.lines())["eviction-hard"], {**DEFAULTS, "memory.available": "200Mi"})

    def test_an_explicit_empty_setting_stays_empty(self):
        # Codex round 1: --eviction-hard="" turned the disk signals off; changing memory keeps them off
        self.write_args('--eviction-hard=""\n--system-reserved=""\n')
        self.assertEqual(kubelet.flags(self.lines()), {"eviction-hard": {}, "system-reserved": {}})
        self.write(z=configz(system={}, evict={}))
        self.assertEqual(self.lines(), ['--eviction-hard="memory.available<200Mi"', "--system-reserved=memory=2Gi"])

    def test_one_setting_alone_leaves_the_other(self):
        self.write(evict="")
        self.assertIn('--eviction-hard="memory.available<100Mi,nodefs.available<1Gi,imagefs.available<1Gi"', self.lines())
        self.assertIn("--system-reserved=memory=2Gi", self.lines())
        self.assertEqual(self.check(evict="")[0], 0)

    def test_the_same_size_written_differently_is_no_change(self):
        self.write_args(MICROK8S_ARGS + "--system-reserved=memory=2048Mi\n")
        self.assertEqual(self.check(evict="")[0], 0)

    def test_refused_when_pods_here_would_not_fit(self):
        rc, msg = self.check(requests=6 * GI)
        self.assertEqual(rc, 2)
        self.assertIn("already ask for 6144 MiB: the kubelet would turn some of them away", msg)
        self.pods_use(6 * GI, 100 * MI)
        rc, msg = self.check(requests=4 * GI)
        self.assertEqual(rc, 2)
        self.assertIn("already use 6044 MiB: the kubelet would start evicting them at once", msg)
        rc, msg = self.check(reserved="8Gi", requests=0)
        self.assertEqual(rc, 2)
        self.assertIn("all of this machine's 7814 MiB", msg)

    def test_bad_values_and_forms(self):
        self.assertEqual(self.check(reserved="lots")[0], 2)
        self.assertIn("isn't a size", self.check(evict="200 MB")[1])
        self.assertEqual(self.check(reserved="10%")[0], 2)          # a share only for the eviction threshold
        self.assertEqual(self.check(evict="3%", requests=0)[0], 1)
        self.write_args("--system-reserved memory=1Gi\n")
        rc, msg = self.check()
        self.assertEqual(rc, 2)
        self.assertIn("with a space", msg)
        self.write_args('--eviction-hard="memory.available=100Mi"\n')
        rc, msg = self.check()
        self.assertEqual(rc, 2)
        self.assertIn("a pair without '<'", msg)
        self.write_args("--kube-reserved=memory=lots\n")
        rc, msg = self.check(requests=0)
        self.assertEqual(rc, 2)
        self.assertIn("kube-reserved memory 'lots' isn't a quantity", msg)
        self.write_args(MICROK8S_ARGS)
        self.assertEqual(self.check(requests=0, z="not json")[0], 2)
        shutil.rmtree(f"{self.cg}/kubepods")
        self.assertEqual(self.check(requests=0)[0], 2)

    def test_shares_and_sizes_match_by_one_rule(self):
        # Codex round 2: the file check and the live check agree on what satisfies the setting
        self.write_args('--eviction-hard="memory.available<5.0%"\n--system-reserved=memory=2Gi\n')
        self.assertEqual(self.check(evict="5%")[0], 0)
        self.assertEqual(kubelet.live(configz(system={"memory": "2Gi"}, evict={"memory.available": "5.0%"}), "2Gi", "5%")[0], 0)
        # a size that happens to equal the share on this machine is a different setting, in both
        self.write_args('--eviction-hard="memory.available<400Mi"\n')
        self.assertEqual(self.check(reserved="", evict="5%", requests=0)[0], 1)
        self.assertEqual(kubelet.live(configz(evict={"memory.available": "400Mi"}), "", "5%")[0], 1)
        self.assertEqual(kubelet.live(configz(evict={"memory.available": "5%"}), "", "400Mi")[0], 1)
        self.write(reserved="", evict="5%")
        self.assertEqual(self.lines(), ['--eviction-hard="memory.available<5%"'])

    def test_spaces_around_a_value_are_not_written(self):
        # Codex round 2: kubelite splits an args-file line at spaces, so " 2Gi " would make two arguments
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kubelet.main(["kubelet.py", "check", self.args, " 2Gi ", " 200Mi ", self.meminfo, self.cg]), 3)
        z = running(self.text())
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(z)
            self.assertEqual(kubelet.main(["kubelet.py", "write", self.args, " 2Gi ", " 200Mi "]), 0)
        finally:
            sys.stdin = stdin
        self.assertIn("--system-reserved=memory=2Gi", self.lines())
        self.assertIn('--eviction-hard="memory.available<200Mi,nodefs.available<1Gi,imagefs.available<1Gi"', self.lines())
        for line in self.lines():                      # as kubelite reads it: quotes off, split at spaces
            self.assertEqual(len(line.replace('"', "").split()), 1, line)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kubelet.main(["kubelet.py", "check", self.args, " 2Gi ", "200Mi ", self.meminfo, self.cg]), 0)

    def test_live(self):
        z = configz(system={"memory": "2Gi"}, evict={"memory.available": "200Mi", "nodefs.available": "1Gi"})
        self.assertEqual(kubelet.live(z, "2Gi", "200Mi")[0], 0)
        self.assertEqual(kubelet.live(z, "2048Mi", "")[0], 0)        # the same size
        rc, msg = kubelet.live(z, "3Gi", "200Mi")
        self.assertEqual(rc, 1)
        self.assertIn("loads the args file when kubelite restarts", msg)
        self.assertEqual(kubelet.live(json.dumps({"kubeletconfig": {}}), "2Gi", "")[0], 1)
        self.assertEqual(kubelet.live("not json", "2Gi", "")[0], 2)
        self.assertEqual(kubelet.live("{}", "2Gi", "")[0], 2)

    def test_restore_writes_back_what_the_kubelet_ran(self):
        z = running(MICROK8S_ARGS)
        self.write(z=z)
        kubelet.restore(self.args, "2Gi", "200Mi", z)
        self.assertEqual(kubelet.flags(self.lines()), kubelet.flags(MICROK8S_ARGS.splitlines()) | {"system-reserved": {}})
        self.assertIn('--system-reserved=""', self.lines())          # empty, as the kubelet ran it
        # Codex round 1: an explicit empty setting comes back explicit, not as no flag
        self.write_args('--eviction-hard="memory.available<200Mi"\n--system-reserved=memory=2Gi\n')
        kubelet.restore(self.args, "2Gi", "200Mi", configz(system={}, evict={}))
        self.assertEqual(self.lines(), ['--eviction-hard=""', '--system-reserved=""'])
        # only the flags hb manages
        self.write_args('--eviction-hard="memory.available<200Mi"\n--system-reserved=memory=2Gi\n')
        kubelet.restore(self.args, "", "200Mi", configz(evict={"memory.available": "100Mi"}))
        self.assertEqual(self.lines(), ['--eviction-hard="memory.available<100Mi"', "--system-reserved=memory=2Gi"])

    def test_requests_as_the_kubelet_counts_them(self):
        def pod(phase="Running", containers=(), init=(), overhead=None):
            spec = {"containers": [{"resources": {"requests": {"memory": m}}} if m else {} for m in containers],
                    "initContainers": [{"resources": {"requests": {"memory": m}}} for m in init]}
            if overhead:
                spec["overhead"] = {"memory": overhead}
            return {"status": {"phase": phase}, "spec": spec}
        pods = {"items": [pod(containers=("256Mi", "128Mi", None)), pod(containers=("100Mi",), init=("1Gi",)),
                          pod(phase="Succeeded", containers=("4Gi",)), pod(containers=("64Mi",), overhead="16Mi")]}
        self.assertEqual(kubelet.pod_requests(pods), (384 + 1024 + 80) * MI)

    def test_sidecars_count_beside_the_containers(self):
        def c(mem, always=False):
            out = {"resources": {"requests": {"memory": mem}}}
            if always:
                out["restartPolicy"] = "Always"
            return out

        def req(init, containers):
            return kubelet.pod_request({"spec": {"initContainers": init, "containers": containers}})
        self.assertEqual(req([c("100Mi", True)], [c("300Mi")]), 400 * MI)
        self.assertEqual(req([c("100Mi", True), c("500Mi")], [c("300Mi")]), 600 * MI)
        self.assertEqual(req([c("500Mi"), c("100Mi", True)], [c("300Mi")]), 500 * MI)

    def test_pod_level_requests(self):
        # Codex round 1: spec.resources.requests.memory is the pod's request, before overhead
        pod = {"spec": {"resources": {"requests": {"memory": "7Gi"}}, "containers": [{"name": "a"}],
                        "overhead": {"memory": "16Mi"}}}
        self.assertEqual(kubelet.pod_request(pod), 7 * GI + 16 * MI)

    def test_quantities_the_api_may_send(self):
        # Codex round 1: "7e9" is a valid request, not zero; one hb can't read is refused, not zero
        pod = {"spec": {"containers": [{"name": "a", "resources": {"requests": {"memory": "7e9"}}}]}}
        self.assertEqual(kubelet.pod_request(pod), 7 * 10**9)
        pod["spec"]["containers"][0]["resources"]["requests"]["memory"] = "seven gigs"
        pod["metadata"] = {"namespace": "ns", "name": "p"}
        with self.assertRaisesRegex(ValueError, "pod ns/p container a memory request 'seven gigs'"):
            kubelet.pod_request(pod)

    def test_what_a_resize_has_allocated_counts(self):
        # Codex round 1: the spec went down to 1Gi, but the kubelet still holds 7Gi for it
        pod = {"spec": {"containers": [{"name": "a", "resources": {"requests": {"memory": "1Gi"}}}]},
               "status": {"phase": "Running", "containerStatuses": [
                   {"name": "a", "allocatedResources": {"memory": "7Gi"}, "resources": {"requests": {"memory": "7Gi"}}}]}}
        self.assertEqual(kubelet.pod_request(pod), 7 * GI)
        pod["status"]["containerStatuses"][0] = {"name": "a", "allocatedResources": {"memory": "512Mi"}}
        self.assertEqual(kubelet.pod_request(pod), 1 * GI)               # going up: the spec counts

    def test_a_pod_level_request_added_by_a_resize_keeps_the_old_allocation(self):
        # Codex round 2: a resize adds a 1Gi pod-level request and takes the container from 7Gi to
        # 1Gi; until the kubelet allocates it, a restart admits the old 7Gi
        pod = {"spec": {"resources": {"requests": {"memory": "1Gi"}},
                        "containers": [{"name": "a", "resources": {"requests": {"memory": "1Gi"}}}]},
               "status": {"phase": "Running", "containerStatuses": [
                   {"name": "a", "allocatedResources": {"memory": "7Gi"}, "resources": {"requests": {"memory": "7Gi"}}}]}}
        self.assertEqual(kubelet.pod_request(pod), 7 * GI)
        # once allocated: the pod-level request is what counts
        pod["status"] = {"phase": "Running", "allocatedResources": {"memory": "1Gi"},
                         "containerStatuses": [{"name": "a", "allocatedResources": {"memory": "1Gi"}}]}
        self.assertEqual(kubelet.pod_request(pod), 1 * GI)


if __name__ == "__main__":
    unittest.main()
