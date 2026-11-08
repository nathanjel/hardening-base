"""hb-rebuild: each item against a staged snapshot laid out in a temp folder, with the system's
commands faked; staging itself against a real restic repository."""
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

rebuild = load_tool("rebuild")
ME = pwd.getpwuid(os.getuid())


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class Fake:
    """util.run stand-in: answers by command prefix, records every call."""

    def __init__(self, answers=None):
        self.answers, self.calls = answers or {}, []

    def __call__(self, *cmd, timeout=30, input=None, **kw):
        self.calls.append((cmd, input))
        for prefix, answer in self.answers.items():
            if " ".join(cmd).startswith(prefix):
                return answer(cmd) if callable(answer) else answer
        return 0, "", ""

    def ran(self, prefix):
        return [c for c, _ in self.calls if " ".join(c).startswith(prefix)]


def obj(kind, name, ns=None, api="v1", **extra):
    meta = {"name": name, "uid": "u-" + name, "resourceVersion": "7", "creationTimestamp": "2026-06-01T00:00:00Z",
            "managedFields": [{"manager": "kubectl"}]}
    if ns:
        meta["namespace"] = ns
    meta.update(extra.pop("meta", {}))
    return {"apiVersion": api, "kind": kind, "metadata": meta, "status": {"x": 1}, **extra}


class ItemsTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.stage = os.path.join(self.d, "stage")
        self.cfg = {"rebuild": {"files": [], "data": [], "skip_namespaces": ["kube-system", "cert-manager"]},
                    "backup": {"paths": []}}
        self.ctx = rebuild.Ctx(self.cfg, self.stage, {"id": "abc123", "short_id": "abc1"})
        self.fake = Fake()
        self.addCleanup(setattr, rebuild.util, "run", rebuild.util.run)
        rebuild.util.run = self.fake

    def dump(self, name, text):
        write(self.stage + rebuild.DUMP + "/" + name, text)

    # files
    def test_files_copies_only_what_is_missing(self):
        live = os.path.join(self.d, "live")
        write(os.path.join(live, "kept.repo"), "mine\n")
        write(self.stage + live + "/kept.repo", "from the backup\n")
        write(self.stage + live + "/new.repo", "[antigravity]\n")
        os.chmod(self.stage + live + "/new.repo", 0o640)
        self.cfg["rebuild"]["files"] = [live + "/*.repo"]
        rc, line = rebuild.chk_files(self.ctx)
        self.assertEqual(rc, 1)
        self.assertIn("new.repo", line)
        self.assertNotIn("kept.repo", line)
        self.assertIsNone(rebuild.fix_files(self.ctx))
        with open(os.path.join(live, "kept.repo")) as f:
            self.assertEqual(f.read(), "mine\n")
        self.assertEqual(os.stat(os.path.join(live, "new.repo")).st_mode & 0o777, 0o640)
        self.assertEqual(rebuild.chk_files(self.ctx)[0], 0)

    # packages
    def test_packages(self):
        self.dump("packages.txt", "git\nrestic\nwireguard-tools\n")
        self.fake.answers["rpm -q"] = (1, "git-2.50\npackage restic is not installed\nwireguard-tools-1.0\n", "")
        self.assertEqual(rebuild.chk_packages(self.ctx), (1, "will install 1 of 3 packages: restic"))
        self.assertIsNone(rebuild.fix_packages(self.ctx))
        self.assertEqual(self.fake.ran("dnf"), [("dnf", "install", "-y", "--setopt=strict=False", "restic")])

    def test_no_package_list_is_broken(self):
        self.assertEqual(rebuild.chk_packages(self.ctx)[0], 2)

    # snaps
    def test_snaps(self):
        self.dump("snaps.txt", "Name Version Rev Tracking Publisher Notes\n"
                               "core22 20260909 2987 latest/stable canonical** base,held\n"
                               "microk8s v1.35.6 9072 1.35/stable canonical** classic,held\n"
                               "snapd 2.77.1 28254 latest/stable canonical** snapd,held\n"
                               "mine 0.1 x1 - - -\n"
                               "jq 1.5 6 latest/stable mvo -\n")
        self.fake.answers["snap list"] = (0, "Name Version Rev Tracking Publisher Notes\nsnapd 2.77 1 latest/stable c snapd\n", "")
        rc, line = rebuild.chk_snaps(self.ctx)
        self.assertEqual((rc, line), (1, "will install microk8s (1.35/stable, classic), jq (latest/stable)"))
        self.addCleanup(setattr, rebuild, "SNAP_LINK", rebuild.SNAP_LINK)
        rebuild.SNAP_LINK = os.path.join(self.d, "snap")
        self.assertIsNone(rebuild.fix_snaps(self.ctx))
        self.assertEqual(self.fake.ran("snap install"),
                         [("snap", "install", "microk8s", "--channel", "1.35/stable", "--classic"),
                          ("snap", "install", "jq", "--channel", "latest/stable")])
        self.assertEqual(os.readlink(rebuild.SNAP_LINK), "/var/lib/snapd/snap")

    def test_snaps_wait_for_snapd(self):
        self.dump("snaps.txt", "Name Version Rev Tracking Publisher Notes\njq 1.5 6 latest/stable mvo -\n")
        self.fake.answers["snap list"] = (127, "", "snap: not found")
        self.assertEqual(rebuild.chk_snaps(self.ctx)[0], 1)

    # users
    def stage_accounts(self, extra_passwd=""):
        write(self.stage + "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"
              "hbtestalice:x:45001:45001:Alice:/home/hbtestalice:/bin/bash\n" + extra_passwd)
        write(self.stage + "/etc/group", "hbtestalice:x:45001:\nhbtestdevs:x:45002:hbtestalice\n"
              "hbtestsys:x:900:hbtestalice\n")
        write(self.stage + "/etc/shadow", "hbtestalice:$y$j9T$secret$hash:20000:0:99999:7:::\n")

    def test_users_made_with_their_uid_groups_and_hash(self):
        self.stage_accounts()
        rc, line = rebuild.chk_users(self.ctx)
        self.assertEqual(rc, 1)
        self.assertIn("will make hbtestalice", line)
        err = rebuild.fix_users(self.ctx)
        self.assertIn("group hbtestsys doesn't exist here yet", err)
        self.assertEqual(self.fake.ran("useradd"), [("useradd", "-u", "45001", "-g", "hbtestalice", "-M", "-d",
                                                     "/home/hbtestalice", "-s", "/bin/bash", "-c", "Alice",
                                                     "hbtestalice")])
        self.assertIn(("groupadd", "-g", "45001", "hbtestalice"), self.fake.ran("groupadd"))
        self.assertIn(("groupadd", "-g", "45002", "hbtestdevs"), self.fake.ran("groupadd"))
        chpasswd = [i for c, i in self.fake.calls if c[0] == "chpasswd"]
        self.assertEqual(chpasswd, ["hbtestalice:$y$j9T$secret$hash\n"])
        self.assertFalse([c for c, _ in self.fake.calls if any("$y$" in a for a in c)], "a hash on a command line")

    def test_uid_taken_by_someone_else_is_broken(self):
        self.stage_accounts(f"hbtestbob:x:{ME.pw_uid}:{ME.pw_gid}::/home/hbtestbob:/bin/bash\n")
        rc, line = rebuild.chk_users(self.ctx)
        self.assertEqual(rc, 2)
        self.assertIn(f"uid {ME.pw_uid} of hbtestbob belongs to {ME.pw_name}", line)

    # data
    def test_data_restores_only_missing_top_level_entries(self):
        home, srv = os.path.join(self.d, "home"), os.path.join(self.d, "srv")
        os.makedirs(os.path.join(home, "fedora"))
        self.cfg["rebuild"]["data"] = [home, srv, os.path.join(self.d, "never")]
        nodes = {home: [home, home + "/fedora", home + "/alice"], srv: [srv, srv + "/rec"]}

        def lines(*args):
            for p in nodes.get(args[-1], []):
                yield json.dumps({"struct_type": "node", "path": p}) + "\n"
        streamed = []
        for name, fn in (("lines", lines), ("stream", lambda *a: streamed.append(a) or 0)):
            self.addCleanup(setattr, rebuild.restic, name, getattr(rebuild.restic, name))
            setattr(rebuild.restic, name, fn)
        rc, line = rebuild.chk_data(self.ctx)
        self.assertEqual(rc, 1)
        self.assertIn(f"will restore {home}/alice, {srv}", line)
        self.assertIn("not in the snapshot", line)
        self.assertIsNone(rebuild.fix_data(self.ctx))
        self.assertEqual(streamed, [("restore", "abc123", "--target", "/", "--overwrite", "never",
                                     "--include", home + "/alice", "--include", srv)])

    def test_default_data_is_backup_paths_without_config_and_state(self):
        cfg = {"rebuild": {"data": []}, "backup": {"paths": ["/etc", "/root", "/home", "/usr/local",
                                                             rebuild.util.STATE, "/srv/app"]}}
        self.assertEqual(rebuild.data_paths(cfg), ["/root", "/home", "/srv/app"])

    # addons
    def test_addons_in_order(self):
        self.dump("k8s/addons.txt", "microk8s is running\naddons:\ncore/cert-manager: enabled\ncore/dns: enabled\n"
                                    "core/hostpath-storage: enabled\ncore/registry: enabled\ncore/gpu: disabled\n")
        self.fake.answers["/snap/bin/microk8s status"] = (0, "addons:\ncore/dns: enabled\ncore/registry: disabled\n", "")
        self.assertEqual(rebuild.chk_addons(self.ctx), (1, "will enable hostpath-storage, cert-manager, registry"))
        rebuild.fix_addons(self.ctx)
        self.assertEqual([c[2] for c in self.fake.ran("/snap/bin/microk8s enable")],
                         ["hostpath-storage", "cert-manager", "registry"])

    def test_addons_wait_for_microk8s(self):
        self.dump("k8s/addons.txt", "core/dns: enabled\n")
        self.fake.answers["/snap/bin/microk8s status"] = (127, "", "not found")
        self.assertEqual(rebuild.chk_addons(self.ctx)[0], 1)

    # k8s
    def k8s_dump(self):
        cluster = [obj("Namespace", "shop"), obj("Namespace", "default"), obj("Namespace", "kube-system"),
                   obj("PersistentVolume", "pv-db", spec={"claimRef": {"kind": "PersistentVolumeClaim", "name": "db",
                                                                        "namespace": "shop", "uid": "old",
                                                                        "resourceVersion": "9"}}),
                   obj("PersistentVolume", "pv-reg", spec={"claimRef": {"name": "r", "namespace": "container-registry"}}),
                   obj("ClusterIssuer", "le", api="cert-manager.io/v1",
                       spec={"acme": {"privateKeySecretRef": {"name": "le-account"}}})]
        objects = [
            obj("Deployment", "web", "shop", api="apps/v1", meta={"annotations": {"deployment.kubernetes.io/revision": "4"}}),
            obj("Job", "web-123", "shop", api="batch/v1", meta={"ownerReferences": [{"kind": "CronJob"}]}),
            obj("Job", "migrate", "shop", api="batch/v1"),
            obj("ConfigMap", "kube-root-ca.crt", "shop"),
            obj("ServiceAccount", "default", "shop"),
            obj("Secret", "token", "shop", type="kubernetes.io/service-account-token"),
            obj("Secret", "sh.helm.release.v1.x.v1", "shop", type="helm.sh/release.v1"),
            obj("Secret", "app-env", "shop", type="Opaque"),
            obj("Service", "web", "shop", spec={"clusterIP": "10.152.183.9", "clusterIPs": ["10.152.183.9"]}),
            obj("Service", "db", "shop", spec={"clusterIP": "None"}),
            obj("EndpointSlice", "web-x1", "shop", api="discovery.k8s.io/v1",
                meta={"labels": {"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}}),
            obj("EndpointSlice", "asterisk-host-1", "shop", api="discovery.k8s.io/v1"),
            obj("EndpointSlice", "hb-webshell", "default", api="discovery.k8s.io/v1",
                meta={"labels": {"endpointslice.kubernetes.io/managed-by": "hb"}}),
            obj("Service", "kubernetes", "default"),
            obj("EndpointSlice", "kubernetes", "default", api="discovery.k8s.io/v1"),
            obj("PersistentVolumeClaim", "db", "shop", spec={"volumeName": "pv-db"}),
            obj("Middleware", "redirect", "shop", api="traefik.io/v1alpha1"),
            obj("Secret", "le-account", "cert-manager", type="Opaque"),
            obj("Secret", "cert-manager-webhook-ca", "cert-manager", type="Opaque"),
            obj("Deployment", "coredns", "kube-system", api="apps/v1"),
        ]
        self.dump("k8s/cluster.json", json.dumps({"items": cluster}))
        self.dump("k8s/objects.json", json.dumps({"items": objects}))

    def test_k8s_restores_what_you_made(self):
        self.k8s_dump()
        want = rebuild.wanted_objects(self.ctx)
        names = [f"{o['kind']}/{o['metadata'].get('namespace', '')}/{o['metadata']['name']}" for o in want]
        self.assertEqual(names[0], "Namespace//shop")
        self.assertEqual(names[-1], "ClusterIssuer//le")
        self.assertEqual(sorted(names), sorted([
            "Namespace//shop", "PersistentVolume//pv-db", "ClusterIssuer//le", "Deployment/shop/web",
            "Secret/shop/app-env", "Service/shop/web", "Service/shop/db", "EndpointSlice/shop/asterisk-host-1",
            "EndpointSlice/default/hb-webshell", "PersistentVolumeClaim/shop/db", "Middleware/shop/redirect",
            "Secret/cert-manager/le-account"]))
        self.assertLess(names.index("Secret/cert-manager/le-account"), names.index("ClusterIssuer//le"))
        self.assertLess(names.index("Secret/shop/app-env"), names.index("Deployment/shop/web"))
        by = {n: o for n, o in zip(names, want)}
        for o in want:
            self.assertNotIn("status", o)
            for k in ("uid", "resourceVersion", "creationTimestamp", "managedFields"):
                self.assertNotIn(k, o["metadata"])
        self.assertNotIn("annotations", by["Deployment/shop/web"]["metadata"])
        self.assertNotIn("clusterIP", by["Service/shop/web"]["spec"])
        self.assertEqual(by["Service/shop/db"]["spec"]["clusterIP"], "None")
        self.assertEqual(by["PersistentVolume//pv-db"]["spec"]["claimRef"],
                         {"kind": "PersistentVolumeClaim", "name": "db", "namespace": "shop"})
        self.assertEqual(by["PersistentVolumeClaim/shop/db"]["spec"]["volumeName"], "pv-db")

    def test_k8s_creates_only_missing_objects(self):
        self.k8s_dump()

        def get(cmd):
            t = cmd[3]
            if t == "middleware.traefik.io":
                return 1, "", 'error: the server doesn\'t have a resource type "middleware"'
            items = [obj("Deployment", "web", "shop")] if t == "deployment.apps" else []
            return 0, json.dumps({"items": items}), ""
        self.fake.answers["/snap/bin/microk8s kubectl get"] = get
        rc, line = rebuild.chk_k8s(self.ctx)
        self.assertEqual(rc, 1)
        self.assertIn("will create 10 objects", line)
        self.assertIn("doesn't know middleware.traefik.io yet", line)
        rebuild.fix_k8s(self.ctx)
        creates = [i for c, i in self.fake.calls if c[2:4] == ("create", "-f")]
        self.assertEqual([o["kind"] for o in json.loads(creates[0])["items"]], ["Namespace"])
        rest = json.loads(creates[1])["items"]
        self.assertEqual(len(rest), 9)
        self.assertNotIn("web", [o["metadata"]["name"] for o in rest if o["kind"] == "Deployment"])

    def test_k8s_waits_for_a_cluster(self):
        self.k8s_dump()
        self.fake.answers["/snap/bin/microk8s kubectl version"] = (1, "", "connection refused")
        self.assertEqual(rebuild.chk_k8s(self.ctx), (1, "no cluster yet (the snaps and addons items)"))

    # units
    def test_units(self):
        self.dump("units-enabled.txt", "sshd.service enabled disabled\nhb-status.timer enabled disabled\n"
                                       "getty@.service enabled enabled\nsmb.service enabled disabled\n"
                                       "smartd.service enabled enabled\ngone.service enabled disabled\n")
        self.fake.answers["systemctl list-unit-files"] = (0, "sshd.service enabled disabled\nsmartd.service disabled "
                                                             "enabled\nsmb.service disabled disabled\n", "")
        self.assertEqual(rebuild.chk_units(self.ctx),
                         (1, "will enable smartd.service (from the next boot) (not on this box: gone.service)"))
        rebuild.fix_units(self.ctx)
        self.assertEqual(self.fake.ran("systemctl enable"), [("systemctl", "enable", "smartd.service")])


@unittest.skipUnless(shutil.which("restic"), "restic not installed")
class StageTest(unittest.TestCase):
    def test_staged_once_per_snapshot(self):
        temp_state(self)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        tree = os.path.join(d, "tree")
        write(os.path.join(tree, "etc", "passwd"), "root:x:0:0::/root:/bin/bash\n")
        write(os.path.join(tree, "state", "packages.txt"), "git\n")
        write(os.path.join(tree, "home", "big"), "not staged\n")
        write(os.path.join(d, "pw"), "pw\n")
        env = {"RESTIC_REPOSITORY": os.path.join(d, "repo"), "RESTIC_PASSWORD_FILE": os.path.join(d, "pw"),
               "RESTIC_CACHE_DIR": os.path.join(d, "cache")}
        for k, v in env.items():
            self.addCleanup(os.environ.pop, k, None)
            os.environ[k] = v
        subprocess.run(["restic", "init", "-q"], check=True, capture_output=True)
        subprocess.run(["restic", "backup", "-q", "--host", "box", "--tag", "hb", tree], check=True, capture_output=True)
        self.addCleanup(setattr, rebuild.restic, "COMMAND", rebuild.restic.COMMAND)
        rebuild.restic.COMMAND = ["restic"]
        self.addCleanup(setattr, rebuild, "STAGED", rebuild.STAGED)
        rebuild.STAGED = [tree + "/etc", tree + "/state"]
        ctx = rebuild.prepare({}, host="box")
        self.assertTrue(os.path.isfile(ctx.path(tree + "/etc/passwd")))
        self.assertTrue(os.path.isfile(ctx.path(tree + "/state/packages.txt")))
        self.assertFalse(os.path.exists(ctx.path(tree + "/home")))
        restores = []
        real = rebuild.restic.run
        self.addCleanup(setattr, rebuild.restic, "run", real)
        rebuild.restic.run = lambda *a, **k: (restores.append(a[0]), real(*a, **k))[1]
        rebuild.prepare({}, host="box")
        self.assertNotIn("restore", restores)


if __name__ == "__main__":
    unittest.main()
