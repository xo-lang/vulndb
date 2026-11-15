"""Generate vuln.xolang.org's files from data/reports (decision 0647 of
xo-lang/xo): OSV 1.6 entries at ID/XO-YYYY-NNNN.json and Go's index
layout (index/db.json, index/modules.json, index/vulns.json), plus
vulndb.zip and the root page index.txt. Standard library only; the same
reports give the same bytes.

    python3 -E -s -m vulndb.gen [--reports data/reports] [--releases FILE] OUT
"""

import argparse
import io
import json
import os
import sys
import zipfile

from vulndb import report

BASE = "https://vuln.xolang.org"


def rfc3339(day):
    return day + "T00:00:00Z"


def osv(r):
    affected = []
    for a in r["affected"]:
        events = [{"introduced": a["introduced"]}]
        if "fixed" in a:
            events.append({"fixed": a["fixed"]})
        else:
            events.append({"last_affected": a["last_affected"]})
        e = {
            "package": {"ecosystem": "Xo", "name": a["module"]},
            "ranges": [{"type": "SEMVER", "events": events}],
        }
        if a.get("imports"):
            e["ecosystem_specific"] = {"imports": a["imports"]}
        ds = {k: a[k] for k in ("backends", "platforms") if a.get(k)}
        if ds:
            e["database_specific"] = ds
        affected.append(e)
    out = {
        "schema_version": "1.6.0",
        "id": r["id"],
        "modified": rfc3339(r["modified"]),
        "published": rfc3339(r["published"]),
    }
    if r.get("aliases"):
        out["aliases"] = r["aliases"]
    out["summary"] = r["summary"]
    out["details"] = r["details"]
    out["affected"] = affected
    if r.get("references"):
        out["references"] = r["references"]
    if r.get("credits"):
        out["credits"] = [{"name": c} for c in r["credits"]]
    ds = {"url": f"{BASE}/ID/{r['id']}.json"}
    if r.get("changelog"):
        ds["changelog"] = r["changelog"]
    out["database_specific"] = ds
    return out


def dump(v):
    return (json.dumps(v, indent=1, ensure_ascii=False, sort_keys=False) + "\n").encode("utf-8")


ROOT = """vuln.xolang.org: the vulnerability database of Xo (as vuln.go.dev), in OSV
1.6 format. It covers std (versioned by Xo release), the xo toolchain, and
modules published through proxy.xolang.org. `xo vuln` checks a program's
toolchain, imported std modules and xo.lock against it.

Endpoints:
  GET /index/db.json              when the database last changed
  GET /index/modules.json         each module and the ids of its entries
  GET /index/vulns.json           each entry's id, modified time and aliases
  GET /ID/XO-YYYY-NNNN.json       one entry (OSV 1.6)
  GET /vulndb.zip                 every file above, for offline use

Examples:
  curl https://vuln.xolang.org/index/db.json
  curl https://vuln.xolang.org/ID/{first}.json

Reports: https://github.com/xo-lang/vulndb
Report a vulnerability: https://github.com/xo-lang/xo/security (SECURITY.md)
Advisories: https://xolang.dev/security/
"""


def generate(reports, out):
    files = {}
    mods = {}
    vulns = []
    newest = ""
    for r in sorted(reports, key=lambda r: r["id"]):
        files[f"ID/{r['id']}.json"] = dump(osv(r))
        newest = max(newest, r["modified"])
        vulns.append({"id": r["id"], "modified": rfc3339(r["modified"]), **({"aliases": r["aliases"]} if r.get("aliases") else {})})
        for a in r["affected"]:
            ent = {"id": r["id"], "modified": rfc3339(r["modified"])}
            if "fixed" in a:
                ent["fixed"] = a["fixed"]
            lst = mods.setdefault(a["module"], [])
            if all(x["id"] != r["id"] for x in lst):
                lst.append(ent)
    files["index/modules.json"] = dump([{"path": m, "vulns": mods[m]} for m in sorted(mods)])
    files["index/vulns.json"] = dump(vulns)
    files["index/db.json"] = dump({"modified": rfc3339(newest) if newest else "1970-01-01T00:00:00Z"})
    first = vulns[0]["id"] if vulns else "XO-2026-0001"
    files["index.txt"] = ROOT.replace("{first}", first).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            if name == "index.txt":
                continue
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, files[name])
    files["vulndb.zip"] = buf.getvalue()
    for name, data in files.items():
        p = os.path.join(out, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="data/reports")
    ap.add_argument("--releases", default="data/releases.txt", help="released Xo versions, one a line")
    ap.add_argument("out")
    a = ap.parse_args(argv)
    released = None
    if a.releases and os.path.exists(a.releases):
        released = {l.strip() for l in open(a.releases) if l.strip() and not l.startswith("#")}
    rs = report.load(a.reports)
    for r in rs:
        report.check(r, released)
    files = generate(rs, a.out)
    print(f"vulndb: {len(rs)} entries, {len(files)} files in {a.out}")


if __name__ == "__main__":
    sys.exit(main())
