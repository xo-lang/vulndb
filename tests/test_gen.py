import json
import os
import tempfile
import unittest
import zipfile

from vulndb import gen, report

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS = os.path.join(HERE, "data", "reports")
RELEASES = os.path.join(HERE, "data", "releases.txt")


def released():
    with open(RELEASES) as f:
        return {l.strip() for l in f if l.strip() and not l.startswith("#")}


class Reports(unittest.TestCase):
    def test_every_report_checks(self):
        rs = report.load(REPORTS)
        self.assertGreater(len(rs), 0)
        rel = released()
        for r in rs:
            with self.subTest(r["id"]):
                report.check(r, rel)

    def test_ids_count_up_per_year(self):
        by_year = {}
        for r in report.load(REPORTS):
            y, n = r["id"].split("-")[1:]
            by_year.setdefault(y, []).append(int(n))
        for y, ns in by_year.items():
            self.assertEqual(sorted(ns), list(range(1, len(ns) + 1)), y)

    def test_check_refuses(self):
        good = {"id": "XO-2026-0001", "published": "2026-11-01", "modified": "2026-11-02", "summary": "s", "details": "d",
                "affected": [{"module": "std", "introduced": "0", "fixed": "0.50.1", "imports": [{"path": "std/png", "symbols": []}]}]}
        report.check(good, {"0.50.1"})
        bad = [
            ("id", "XO-26-1"),
            ("summary", "two\nlines"),
            ("modified", "2026-10-01"),
        ]
        for k, v in bad:
            r = dict(good, **{k: v})
            with self.subTest(k), self.assertRaises(report.ReportError):
                report.check(r)
        for a in [
            {"module": "std", "introduced": "0"},  # no end
            {"module": "std", "introduced": "0", "fixed": "0.50.1", "last_affected": "0.50.1"},
            {"module": "std", "introduced": "0.51.0", "fixed": "0.50.1"},
            {"module": "std", "introduced": "0", "fixed": "0.50.1", "backends": ["jvm"]},
            {"module": "std", "introduced": "0", "fixed": "0.50.1", "imports": [{"path": "png"}]},
            {"module": "Std", "introduced": "0", "fixed": "0.50.1"},
        ]:
            r = dict(good, affected=[a])
            with self.subTest(a=a), self.assertRaises(report.ReportError):
                report.check(r)
        with self.assertRaises(report.ReportError):
            report.check(good, {"0.51.0"})  # fixed is no release


class Generate(unittest.TestCase):
    def build(self):
        out = tempfile.mkdtemp()
        files = gen.generate(report.load(REPORTS), out)
        return out, files

    def test_same_bytes_twice(self):
        _, a = self.build()
        _, b = self.build()
        self.assertEqual(a, b)

    def test_indexes_match_entries(self):
        out, files = self.build()
        rs = {r["id"]: r for r in report.load(REPORTS)}
        vulns = json.loads(files["index/vulns.json"])
        self.assertEqual(sorted(v["id"] for v in vulns), sorted(rs))
        mods = json.loads(files["index/modules.json"])
        for m in mods:
            for v in m["vulns"]:
                self.assertIn(f"ID/{v['id']}.json", files)
                r = rs[v["id"]]
                self.assertIn(m["path"], [a["module"] for a in r["affected"]])
        db = json.loads(files["index/db.json"])
        self.assertEqual(db["modified"], max(v["modified"] for v in vulns))
        with zipfile.ZipFile(os.path.join(out, "vulndb.zip")) as z:
            self.assertEqual(sorted(z.namelist()), sorted(n for n in files if n not in ("index.txt", "vulndb.zip")))

    def test_osv_shape(self):
        _, files = self.build()
        for name, data in files.items():
            if not name.startswith("ID/"):
                continue
            e = json.loads(data)
            with self.subTest(name):
                self.assertEqual(e["schema_version"], "1.6.0")
                for k in ("id", "modified", "published", "summary", "details", "affected"):
                    self.assertIn(k, e)
                for a in e["affected"]:
                    self.assertEqual(a["package"]["ecosystem"], "Xo")
                    ev = a["ranges"][0]["events"]
                    self.assertEqual(a["ranges"][0]["type"], "SEMVER")
                    self.assertIn("introduced", ev[0])
                    self.assertTrue("fixed" in ev[1] or "last_affected" in ev[1])

    def test_root_page(self):
        _, files = self.build()
        t = files["index.txt"].decode()
        self.assertIn("GET /index/modules.json", t)
        self.assertIn("curl https://vuln.xolang.org/ID/XO-", t)


if __name__ == "__main__":
    unittest.main()
