"""hb-dump: which containers get dumped, what a run leaves in /var/lib/hb/dumps, and the verdict."""
import contextlib
import copy
import io
import json
import os
import resource
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402
from hbkit import config  # noqa: E402

dump = load_tool("dump")

PG = ["sh", "-c", 'exec pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"']

# kubectl: `get pods` prints {pods} (or fails when {fail_list} exists); `exec -n NS POD -c C -- ...`
# logs its arguments, then for files in {d} named after NS-POD: noisy- (its bytes of error output
# first), fail- (an error, exit 1), term- (SIGTERM to itself, as many times as it says), code-
# (that exit code, silently), empty- (nothing), big- (its bytes of output); otherwise it prints a
# dump naming where it ran and the command it was given.
KUBECTL = """#!/bin/sh
d={d}
case "$1" in
  get) [ -e "$d/fail-list" ] && {{ echo "The connection to the server was refused" >&2; exit 1; }}
       cat "$d/pods.json" ;;
  exec) echo "$*" >> "$d/exec.log"
        ns="$3" pod="$4" c="$6"; shift 7
        [ -e "$d/noisy-$ns-$pod" ] && {{ head -c "$(cat "$d/noisy-$ns-$pod")" /dev/zero | tr '\\0' e; echo; }} >&2
        [ -e "$d/fail-$ns-$pod" ] && {{ echo "pg_dump: warning: something"; echo "pg_dump: error: connection failed" >&2; exit 1; }}
        [ -e "$d/term-$ns-$pod" ] && {{ n=$(cat "$d/term-$ns-$pod"); [ "$n" -gt 0 ] && {{ echo $((n - 1)) > "$d/term-$ns-$pod"; kill -TERM $$; }}; }}
        [ -e "$d/code-$ns-$pod" ] && exit "$(cat "$d/code-$ns-$pod")"
        [ -e "$d/empty-$ns-$pod" ] && exit 0
        [ -e "$d/big-$ns-$pod" ] && {{ head -c "$(cat "$d/big-$ns-$pod")" /dev/zero; exit 0; }}
        echo "-- dump of $ns/$pod/$c: $*" ;;
esac
"""


def pod(ns, name, *containers, phase="Running", deleting=False):
    meta = {"namespace": ns, "name": name}
    if deleting:
        meta["deletionTimestamp"] = "2026-11-09T04:00:00Z"
    return {"metadata": meta, "status": {"phase": phase},
            "spec": {"containers": [{"name": c, "image": i} for c, i in containers]}}


PODS = [
    pod("shop", "postgres-0", ("postgres", "postgres:16-alpine")),
    pod("team-a", "postgresql-0", ("postgresql", "docker.io/bitnami/postgresql:17.2.0@sha256:abc")),
    pod("team-b", "postgresql-0", ("postgresql", "docker.io/bitnami/postgresql:17")),          # another node
    pod("team-new", "postgresql-0", ("postgresql", "bitnami/postgresql:17"), phase="Pending"),
    pod("team-gone", "postgresql-0", ("postgresql", "bitnami/postgresql:17"), deleting=True),
    pod("jobs", "migrate-x1", ("postgresql", "bitnami/postgresql:17"), phase="Succeeded"),
    pod("mon", "exporter", ("exporter", "prometheuscommunity/postgres-exporter:v0.15")),
    pod("web", "app", ("app", "localhost:32000/app:3")),
]
SHOP, TEAM_A, TEAM_B = "shop/postgres-0/postgres.sql", "team-a/postgresql-0/postgresql.sql", "team-b/postgresql-0/postgresql.sql"


class DumpTest(unittest.TestCase):
    def setUp(self):
        self.state = temp_state(self)
        self.addCleanup(shutil.rmtree, self.state, True)
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(f"{d}/kubectl", "w") as f:
            f.write(KUBECTL.format(d=d))
        os.chmod(f"{d}/kubectl", 0o755)
        self.addCleanup(setattr, dump, "KUBECTL", dump.KUBECTL)
        dump.KUBECTL = [f"{d}/kubectl"]
        self.pods(PODS)

    def pods(self, items):
        with open(f"{self.d}/pods.json", "w") as f:
            json.dump({"items": items}, f)

    def cfg(self, dumps=None, paths=("/etc", "/var/lib/hb"), max_mb=None):
        c = copy.deepcopy(config.DEFAULTS)
        c["backup"]["dumps"] = [{"images": ["postgres", "postgresql"], "command": PG}] if dumps is None else dumps
        c["backup"]["paths"] = [p.replace("/var/lib/hb", self.state) for p in paths]
        if max_mb is not None:
            c["backup"]["dumps_max_mb"] = max_mb
        return c

    def run_dumps(self, cfg=None):
        return dump.dump_all((cfg or self.cfg())["backup"])

    def files(self):
        root = dump.folder()
        return sorted(os.path.relpath(os.path.join(a, f), root) for a, _, fs in os.walk(root) for f in fs)

    def read(self, rel):
        with open(os.path.join(dump.folder(), rel)) as f:
            return f.read()

    def touch(self, name, text=""):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(text)

    def execs(self):
        try:
            with open(f"{self.d}/exec.log") as f:
                return len(f.readlines())
        except FileNotFoundError:
            return 0

    # --- rules -------------------------------------------------------------------------------

    def test_image_names(self):
        for image, name in (("postgres", "postgres"), ("postgres:16-alpine", "postgres"),
                            ("docker.io/library/postgres:17@sha256:ab", "postgres"),
                            ("localhost:32000/postgres:16", "postgres"), ("localhost:32000/postgres", "postgres"),
                            ("quay.io/x/postgres-exporter:v1", "postgres-exporter")):
            self.assertEqual(dump.image_name(image), name, image)

    def test_rules_are_checked(self):
        ok = {"images": ["postgres"], "command": PG}
        self.assertIsNone(dump.rules_problem([]))
        self.assertIsNone(dump.rules_problem([ok, {"images": ["mariadb"], "command": ["x"], "suffix": ".sql.gz"}]))
        for bad, word in (({"images": "postgres", "command": PG}, "images must be a list"),
                          ({"images": [], "command": PG}, "images must be a list"),
                          ({"images": ["bitnami/postgresql"], "command": PG}, "own name only"),
                          ({"images": ["postgres:16"], "command": PG}, "own name only"),
                          ({"images": ["mysql"], "command": "mysqldump"}, "command must be"),
                          ({"images": ["mysql"], "command": []}, "command must be"),
                          ({"images": ["mysql"], "command": ["x"], "suffix": "/../x"}, "suffix"),
                          ({"images": ["mysql"], "command": ["x"], "user": "root"}, "unknown keys user"),
                          ("postgres", "must be a table")):
            self.assertIn(word, dump.rules_problem([bad]) or "", bad)
        self.assertIn("already in rule 1", dump.rules_problem([ok, {"images": ["postgres"], "command": ["y"]}]))
        self.assertIn("must be a list", dump.rules_problem({"images": ["postgres"]}))

    def test_the_size_limit_is_checked(self):
        self.assertIsNone(dump.settings_problem(self.cfg()["backup"]))
        for bad in (0, -1, True, "10", 1.5):
            rc, line = dump.verdict(self.cfg(max_mb=bad))
            self.assertEqual((rc, line), (2, "fail: backup.dumps_max_mb must be a whole number of MB above 0"), bad)

    # --- what gets dumped ------------------------------------------------------------------------

    def test_running_pods_of_the_images_on_any_node(self):
        found = dump.targets({"items": PODS}, self.cfg()["backup"]["dumps"])
        self.assertEqual([(t["key"], t["why"]) for t in found], [
            (SHOP, None),
            (TEAM_A, None),
            (TEAM_B, None),
            ("team-new/postgresql-0/postgresql.sql", "pod Pending"),       # should be running: owed a dump
        ])                                                                 # deleting, finished, exporter, app: not
        self.assertEqual(found[0]["command"], PG)

    def test_a_run_writes_each_dump_and_a_record(self):
        rec = self.run_dumps()
        self.assertEqual(self.files(), ["hb-dump.json", SHOP, TEAM_A, TEAM_B])
        self.assertEqual(self.read(TEAM_A), f"-- dump of team-a/postgresql-0/postgresql: {' '.join(PG)}\n")
        with open(f"{self.d}/exec.log") as f:
            first = f.readline().split()
        self.assertEqual(first[:7], ["exec", "-n", "shop", "postgres-0", "-c", "postgres", "--"])
        d = rec["dumps"]
        self.assertTrue(d[TEAM_B]["ok"])
        self.assertEqual(d["team-new/postgresql-0/postgresql.sql"]["error"], "pod Pending")
        self.assertIsNone(d["team-new/postgresql-0/postgresql.sql"]["last_ok"])
        self.assertEqual(json.loads(self.read("hb-dump.json")), rec)     # the snapshot says what it has
        for rel in ("", "shop", "shop/postgres-0", SHOP):                 # root's only
            mode = stat.S_IMODE(os.stat(os.path.join(dump.folder(), rel)).st_mode)
            self.assertEqual(mode & 0o077, 0, rel)

    def test_a_failed_dump_leaves_no_file_and_says_why(self):
        self.touch("fail-team-a-postgresql-0")
        self.touch("empty-shop-postgres-0")
        rec = self.run_dumps()
        self.assertEqual(rec["dumps"][TEAM_A]["error"], "exit 1: pg_dump: error: connection failed")
        self.assertEqual(rec["dumps"][SHOP]["error"], "it wrote nothing")
        self.assertEqual(self.files(), ["hb-dump.json", TEAM_B])        # no .partial either

    def test_a_dump_killed_by_a_signal_hb_didnt_send_runs_once_more(self):
        # snap's scope for kubectl ends when root's user manager stops (a sudo or root's cron job ended)
        self.pods(PODS[:3])
        self.touch("term-shop-postgres-0", "1")
        self.touch("term-team-a-postgresql-0", "2")
        self.touch("code-team-b-postgresql-0", "3")
        d = self.run_dumps()["dumps"]
        self.assertEqual((d[SHOP]["ok"], d[SHOP]["retried"]), (True, "killed by SIGTERM"))
        self.assertEqual(d[TEAM_A]["error"], "killed by SIGTERM (twice)")
        self.assertEqual(d[TEAM_B]["error"], "exit 3")                   # no stray colon without a message
        self.assertNotIn("retried", d[TEAM_B])                            # an exit code isn't retried
        self.assertEqual(self.files(), ["hb-dump.json", SHOP])
        self.assertEqual(self.execs(), 2 + 2 + 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            dump.do_status(self.cfg())
        self.assertIn("(run twice: the first killed by SIGTERM)", out.getvalue())

    def test_the_folder_holds_only_the_last_run(self):
        self.run_dumps()
        stale = os.path.join(dump.folder() + ".new", "left-over")      # an interrupted run's folder
        os.makedirs(os.path.dirname(stale))
        open(stale, "w").close()
        self.pods([PODS[0]])
        self.run_dumps()
        self.assertEqual(self.files(), ["hb-dump.json", SHOP])
        self.assertFalse(os.path.exists(dump.folder() + ".new"))
        self.assertFalse(os.path.exists(dump.folder() + ".old"))

    def test_two_matching_containers_in_one_pod_get_their_own_files(self):
        self.pods([pod("db", "pair-0", ("main", "postgres:16"), ("replica", "postgres:16"), ("side", "busybox"))])
        self.run_dumps()
        self.assertEqual(self.files(), ["db/pair-0/main.sql", "db/pair-0/replica.sql", "hb-dump.json"])

    def test_names_that_look_alike_never_share_a_file(self):
        # pod db with containers a and b, and pod db.a with a: once all "review/db.a.sql"
        self.pods([pod("review", "db", ("a", "postgres:16"), ("b", "postgres:16")),
                   pod("review", "db.a", ("a", "postgres:16"))])
        rec = self.run_dumps()
        self.assertEqual(self.files(), ["hb-dump.json", "review/db.a/a.sql", "review/db/a.sql", "review/db/b.sql"])
        self.assertEqual(len(rec["dumps"]), 3)
        self.assertEqual(self.read("review/db.a/a.sql"), f"-- dump of review/db.a/a: {' '.join(PG)}\n")
        self.assertEqual(self.read("review/db/a.sql"), f"-- dump of review/db/a: {' '.join(PG)}\n")
        self.assertRegex(dump.verdict(self.cfg())[1], r"^ok: 3 databases dumped")

    def test_a_pod_listed_twice_is_dumped_once(self):
        self.pods([PODS[0], PODS[0]])
        rec = self.run_dumps()
        self.assertEqual(self.files(), ["hb-dump.json", SHOP])
        self.assertEqual(self.execs(), 1)
        self.assertEqual(len(rec["dumps"]), 1)          # one key: the second one never replaced the first
        self.assertTrue(rec["dumps"][SHOP]["ok"])
        found = dump.targets({"items": [PODS[0], PODS[0]]}, self.cfg()["backup"]["dumps"])
        self.assertEqual([t["key"] for t in found], [SHOP])

    def test_a_name_unfit_for_a_file_is_never_used(self):
        self.pods([pod("ok", "../../etc", ("postgres", "postgres:16")), pod("Bad_NS", "db-0", ("postgres", "postgres:16")),
                   pod("ok", "db-0", ("pg.main", "postgres:16"))])           # container names have no dots
        rec = self.run_dumps()
        self.assertEqual(self.files(), ["hb-dump.json"])
        self.assertEqual({d["error"] for d in rec["dumps"].values()}, {"a name hb won't use in a file name"})
        self.assertEqual(len(rec["dumps"]), 3)
        self.assertEqual(self.execs(), 0)

    def test_when_pods_cant_be_listed_what_was_there_is_still_owed(self):
        first = self.run_dumps()
        self.touch("fail-list")
        rec = self.run_dumps()
        self.assertEqual(rec["error"], "kubectl get pods: The connection to the server was refused")
        self.assertEqual(self.files(), ["hb-dump.json"])
        d = rec["dumps"][TEAM_B]
        self.assertEqual((d["ok"], d["last_ok"]), (False, first["ts"]))

    # --- what a container sends is bounded ------------------------------------------------------

    def test_a_run_takes_at_most_dumps_max_mb(self):
        self.pods(PODS[:3])
        self.touch("big-shop-postgres-0", "600000")
        self.touch("big-team-a-postgresql-0", "600000")
        d = self.run_dumps(self.cfg(max_mb=1))["dumps"]
        self.assertEqual((d[SHOP]["ok"], d[SHOP]["bytes"]), (True, 600000))
        self.assertEqual(d[TEAM_A]["error"], "stopped at 0.4 MB, all that was left of backup.dumps_max_mb")
        self.assertTrue(d[TEAM_B]["ok"])                                  # small: it fits in what's left
        self.assertEqual(self.files(), ["hb-dump.json", SHOP, TEAM_B])    # nothing of the stopped one
        self.touch("big-shop-postgres-0", "1000000")                      # exactly all of it
        d = self.run_dumps(self.cfg(max_mb=1))["dumps"]
        self.assertTrue(d[SHOP]["ok"])
        for key in (TEAM_A, TEAM_B):
            self.assertEqual(d[key]["error"], "not run: this run's dumps took all of backup.dumps_max_mb (1 MB)")
        self.assertEqual(self.execs(), 3 + 1)                             # team-a and team-b weren't run

    def test_error_output_is_never_kept_whole(self):
        self.pods(PODS[:2])
        self.touch("noisy-shop-postgres-0", str(64 << 20))
        self.touch("noisy-team-a-postgresql-0", str(1 << 20))
        self.touch("fail-team-a-postgresql-0")
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss          # KiB
        d = self.run_dumps()["dumps"]
        grew = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - peak
        self.assertTrue(d[SHOP]["ok"])                                    # 64 MiB of warnings, then a good dump
        self.assertLess(grew, 16 << 10)                                   # under 16 MiB more, at its peak
        self.assertEqual(d[TEAM_A]["error"], "exit 1: pg_dump: error: connection failed")    # its end is kept

    def test_a_dump_never_takes_the_disk_under_min_free(self):
        self.pods(PODS[:1])
        with mock.patch.object(dump, "disk_room", return_value=0):
            d = self.run_dumps()["dumps"]
        self.assertEqual(d[SHOP]["error"], "not run: the disk has under 10% free")
        self.assertEqual(self.execs(), 0)
        # 100 MiB with 10 MiB + 4 KiB free: room for 4 KiB. A 1 MiB dump, far below one look at
        # the disk per SPACE_EVERY, is stopped before it takes the disk under 10% free.
        self.touch("big-shop-postgres-0", str(1 << 20))
        fs = os.statvfs_result((4096, 4096, 25600, 2561, 2561, 0, 0, 0, 0, 255))
        with mock.patch.object(dump.os, "statvfs", return_value=fs):
            self.assertEqual(dump.disk_room(self.state), 4096)
            d = self.run_dumps()["dumps"]
        self.assertEqual(d[SHOP]["error"], "stopped: the disk would have under 10% free")
        self.assertEqual(self.files(), ["hb-dump.json"])
        # what others write meanwhile: the disk is measured again every SPACE_EVERY bytes
        self.touch("big-shop-postgres-0", "1000000")
        with mock.patch.object(dump, "SPACE_EVERY", 100000), \
                mock.patch.object(dump, "disk_room", side_effect=[10**9, 10**9, 10**9, 0]):
            d = self.run_dumps()["dumps"]                 # before it, at its start, twice while it writes
        self.assertEqual(d[SHOP]["error"], "stopped: the disk would have under 10% free")
        self.assertEqual(self.files(), ["hb-dump.json"])
        with mock.patch.object(dump, "MIN_FREE_PERCENT", 0):
            self.assertGreater(dump.disk_room(self.state), 0)
        with mock.patch.object(dump, "MIN_FREE_PERCENT", 101):
            self.assertLessEqual(dump.disk_room(self.state), 0)

    # --- a run cut short between its two renames --------------------------------------------------

    def cut_swap(self):
        """A run that stops after moving the folder aside, before its own takes its place."""
        real = os.rename

        def rename(src, dst):
            if src == dump.folder() + ".new" and dst == dump.folder():
                raise KeyboardInterrupt
            return real(src, dst)
        with mock.patch.object(dump.os, "rename", side_effect=rename), self.assertRaises(KeyboardInterrupt):
            self.run_dumps()
        self.assertFalse(os.path.exists(dump.folder()))

    def test_a_cut_swap_keeps_the_history_of_a_failing_dump(self):
        self.pods(PODS[:1])
        self.touch("fail-shop-postgres-0")
        self.run_dumps()
        self.aged(72)                                                      # failing for 72 h
        self.cut_swap()
        self.assertEqual(dump.verdict(self.cfg())[0], 2)                   # the finished run's record counts
        self.run_dumps()                                                   # finishes that swap first
        rc, line = dump.verdict(self.cfg())
        self.assertEqual(rc, 2, line)
        self.assertLess(dump.read_record()["dumps"][SHOP]["first_seen"], time.time() - 70 * 3600)
        self.assertFalse(os.path.exists(dump.folder() + ".new"))
        self.assertFalse(os.path.exists(dump.folder() + ".old"))

    def test_after_a_cut_swap_the_disk_holds_two_generations_at_most(self):
        self.pods(PODS[:1])
        self.run_dumps()
        self.cut_swap()                                   # left: dumps.old (run 1), dumps.new (run 2)
        seen, real = [], dump.dump_one

        def spy(t, dest, limit):                          # what's on disk while run 3 dumps
            seen.append(sorted(os.path.basename(p) for p in (dump.folder(), dump.folder() + ".new", dump.folder() + ".old")
                               if os.path.exists(p)))
            return real(t, dest, limit)
        with mock.patch.object(dump, "dump_one", spy):
            self.run_dumps()
        self.assertEqual(seen, [["dumps", "dumps.new"]])  # run 2's dumps, recovered, and run 3's own
        self.assertEqual(self.files(), ["hb-dump.json", SHOP])

    def test_a_cut_swap_with_an_unreadable_new_record_goes_back_to_the_run_before(self):
        self.pods(PODS[:1])
        self.touch("fail-shop-postgres-0")
        self.run_dumps()
        self.aged(72)
        self.cut_swap()
        with open(os.path.join(dump.folder() + ".new", "hb-dump.json"), "w") as f:
            f.write("{")                                                   # lost in a power cut
        self.assertIsNotNone(dump.read_record())                           # the run before's record
        self.run_dumps()
        self.assertLess(dump.read_record()["dumps"][SHOP]["first_seen"], time.time() - 70 * 3600)
        self.assertEqual(dump.verdict(self.cfg())[0], 2)

    # --- the verdict ---------------------------------------------------------------------------

    def aged(self, hours):
        """Move the last run's record back by hours."""
        path = os.path.join(dump.folder(), "hb-dump.json")
        with open(path) as f:
            rec = json.load(f)
        shift = hours * 3600
        rec["ts"] -= shift
        for d in rec["dumps"].values():
            d["first_seen"] -= shift
            d["last_ok"] = d["last_ok"] and d["last_ok"] - shift
        with open(path, "w") as f:
            json.dump(rec, f)

    def test_verdicts(self):
        self.assertEqual(dump.verdict(self.cfg(dumps=[])), (0, "ok: not configured (backup.dumps is empty)"))
        self.assertEqual(dump.verdict(self.cfg(dumps=[{"images": "x"}]))[0], 2)
        rc, line = dump.verdict(self.cfg())
        self.assertEqual(rc, 1)
        self.assertIn("no dumps yet", line)
        self.pods(PODS[:3])
        self.run_dumps()
        rc, line = dump.verdict(self.cfg())
        self.assertEqual(rc, 0, line)
        self.assertRegex(line, r"^ok: 3 databases dumped 0 h ago, 0\.0 MB$")
        rc, line = dump.verdict(self.cfg(paths=("/etc",)))
        self.assertEqual(rc, 1)
        self.assertIn("/dumps isn't in backup.paths", line)

    def test_a_failure_warns_and_fails_once_it_lasts(self):
        self.pods(PODS[:3])
        self.run_dumps()
        self.touch("fail-team-b-postgresql-0")
        self.aged(24)
        self.run_dumps()                                   # night two: team-b fails
        rc, line = dump.verdict(self.cfg())
        self.assertEqual((rc, line), (1, "warn: 1 of 3 database dumps failed (sudo hb dump status)"))
        self.aged(24)                                      # night three fails as well: 50 h on, fail
        self.run_dumps()
        rc, line = dump.verdict(self.cfg(), now=time.time() + 2 * 3600)
        self.assertEqual(rc, 2, line)
        self.assertEqual(line, "fail: 1 database without a good dump for 50 h or more (sudo hb dump status)")

    def test_a_new_database_that_never_dumps_fails_after_fail_hours(self):
        self.touch("fail-shop-postgres-0")
        self.pods(PODS[:1])
        self.run_dumps()
        self.assertEqual(dump.verdict(self.cfg())[0], 1)
        self.aged(20)
        self.run_dumps()
        self.assertEqual(dump.verdict(self.cfg(), now=time.time() + 25 * 3600)[0], 1)    # first seen 45 h before
        self.assertEqual(dump.verdict(self.cfg(), now=time.time() + 31 * 3600)[0], 1)    # an old run: counted to it
        self.aged(20)
        self.run_dumps()
        self.assertEqual(dump.verdict(self.cfg(), now=time.time() + 11 * 3600)[0], 2)

    def test_runs_that_stop_only_warn_here(self):
        self.pods(PODS[:2])
        self.touch("fail-shop-postgres-0")
        self.run_dumps()
        self.aged(100)                                     # no run for days: hb backup check fails for it
        rc, line = dump.verdict(self.cfg())
        self.assertEqual(rc, 1, line)
        self.assertTrue(line.startswith("warn: last dump run 100 h ago; 1 of 2 database dumps failed"), line)

    def test_nothing_matched_and_a_failed_listing_warn(self):
        self.pods(PODS[-1:])
        self.run_dumps()
        self.assertEqual(dump.verdict(self.cfg()),
                         (1, "warn: backup.dumps matched no container (sudo hb dump list)"))
        self.touch("fail-list")
        self.run_dumps()
        self.assertEqual(dump.verdict(self.cfg()), (1, "warn: the pods couldn't be listed (sudo hb dump status)"))


if __name__ == "__main__":
    unittest.main()
