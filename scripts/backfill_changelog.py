"""backfill_changelog.py CHANGELOG OUTDIR [--today YYYY-MM-DD]: one report per
`Security (...)` line of xo-lang/xo's CHANGELOG.md (decision 0647 stage 2),
written to OUTDIR/XO-YYYY-NNNN.json in release order (oldest first), and
data/releases.txt's list (every `## vX.Y.Z` section) to stdout.

The range: a line in a release's section was fixed in that release; its
`Affected: A to B` gives introduced A, `Affected: B and earlier` (or no
range) introduced 0. A line under Unreleased has no fixed release yet:
last_affected is B, else the newest release. Each report keeps the line as
`changelog`; the symbols are the backticked `module.name` forms of the line
that name its std modules, a start a reviewer corrects. Standard library
only. Run once for the backfill; later entries are written by hand.
"""

import json
import os
import re
import sys

SEC = re.compile(r"^- (?:\*\*)?Security(?: \(([^)]*)\))?(?:\*\*)?:\s*(.*)$")
# a line with no (scope): the std module its text names
UNSCOPED = [(re.compile(r"\b(untar|unzip|archive)\b"), "std/archive")]
HEAD = re.compile(r"^## (v(\d+\.\d+\.\d+) \((\d{4}-\d{2}-\d{2})\)|Unreleased)")
BACKEND_WORDS = {
    "native": "native", "llvm": "llvm", "go": "go", "wasm": "wasm", "webassembly": "wasm",
}
PLATFORM_WORDS = {"macos": "macOS", "windows": "Windows", "linux": "Linux", "arm64": "arm64", "amd64": "amd64"}


def parse_scope(scope):
    mods, backends, platforms, toolchain = [], set(), set(), False
    for part in re.split(r"[,;]", scope):
        p = part.strip()
        if not p:
            continue
        m = re.match(r"^(std/[a-z0-9_/]+)", p)
        if m:
            path = m.group(1)
            if path == "std/native/llrt/rsa":
                path = "std/crypto"
            mods.append(path)
            continue
        if p.startswith("prelude"):
            mods.append("std/prelude")
            continue
        if "xo build" in p or "xo mod" in p:
            toolchain = True
            continue
        words = re.findall(r"[A-Za-z]+", p.lower())
        if "every" in words or "all" in words:
            continue
        for w in words:
            if w in BACKEND_WORDS:
                backends.add(BACKEND_WORDS[w])
            if w in PLATFORM_WORDS:
                platforms.add(PLATFORM_WORDS[w])
    return mods, sorted(backends), sorted(platforms), toolchain


def symbols(text, path):
    short = path.rsplit("/", 1)[-1]
    out = []
    for tick in re.findall(r"`([^`]+)`", text):
        m = re.match(rf"^{re.escape(short)}\.([A-Za-z_][A-Za-z0-9_]*)", tick)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def summary_of(text):
    s = re.sub(r"\s+", " ", text).strip()
    # the first ". " or "; " outside parentheses and backticks
    cut, depth, tick = len(s), 0, False
    for i, ch in enumerate(s):
        if ch == "`":
            tick = not tick
        elif not tick and ch == "(":
            depth += 1
        elif not tick and ch == ")" and depth:
            depth -= 1
        elif not tick and depth == 0 and ch in ".;" and s[i + 1 : i + 2] == " " and i > 0:
            cut = i
            break
    s = s[:cut].rstrip(".")
    if len(s) > 200:
        s = s[:197].rsplit(" ", 1)[0] + "..."
    return s


def main(argv):
    changelog, outdir = argv[1], argv[2]
    today = "2026-11-15"
    if "--today" in argv:
        today = argv[argv.index("--today") + 1]
    section, sdate = None, None
    releases = []
    found = []  # (order key, section, date, scope, text, line)
    for line in open(changelog, encoding="utf-8"):
        line = line.rstrip("\n")
        h = HEAD.match(line)
        if h:
            if h.group(1) == "Unreleased":
                section, sdate = "Unreleased", today
            else:
                section, sdate = h.group(2), h.group(3)
                releases.append(section)
            continue
        m = SEC.match(line)
        if m and section:
            scope = m.group(1)
            if scope is None:
                named = re.findall(r"\bstd/[a-z0-9_]+", m.group(2))
                scope = ", ".join(dict.fromkeys(named))
                for rx, mod in UNSCOPED:
                    if not scope and rx.search(m.group(2)):
                        scope = mod
                if not scope:
                    scope = "xo build"
            found.append((section, sdate, scope, m.group(2), line))
    newest = releases[0] if releases else "0.0.1"
    rel_order = {v: i for i, v in enumerate(reversed(releases))}
    found.sort(key=lambda f: (rel_order.get(f[0], len(rel_order)),))
    os.makedirs(outdir, exist_ok=True)
    year_n = {}
    for section, sdate, scope, text, line in found:
        year = sdate[:4]
        year_n[year] = year_n.get(year, 0) + 1
        rid = f"XO-{year}-{year_n[year]:04d}"
        mods, backends, platforms, toolchain = parse_scope(scope)
        aff = re.search(r"Affected: (\d+\.\d+\.\d+) to (\d+\.\d+\.\d+)", text)
        earlier = re.search(r"Affected: (\d+\.\d+\.\d+) and earlier", text) or re.search(r"affects (\d+\.\d+)(?:\.\d+)? and earlier", text)
        introduced = aff.group(1) if aff else "0"
        last = aff.group(2) if aff else (earlier.group(1) if earlier else newest)
        if re.match(r"^\d+\.\d+$", last):
            cands = [v for v in releases if v.startswith(last + ".")]
            last = cands[0] if cands else newest
        rng = {"introduced": introduced}
        if section == "Unreleased":
            rng["last_affected"] = last
        else:
            rng["fixed"] = section
        affected = []
        if mods:
            imports = [{"path": p, "symbols": symbols(text, p)} for p in mods]
            a = {"module": "std", **rng, "imports": imports}
            if backends:
                a["backends"] = backends
            if platforms:
                a["platforms"] = platforms
            affected.append(a)
        if toolchain or not mods:
            a = {"module": "toolchain", **rng}
            if backends:
                a["backends"] = backends
            affected.append(a)
        aliases = sorted(set(re.findall(r"\b(CVE-\d{4}-\d{4,}|GO-\d{4}-\d{4})\b", text)))
        notes = []
        if not aff and not earlier:
            notes.append("introduced not stated in the CHANGELOG: 0 (every release before the fix) until reviewed")
        r = {
            "id": rid,
            "published": sdate,
            "modified": today,
            "summary": f"{scope.split(',')[0].split(';')[0].strip()}: {summary_of(text)}",
            "details": re.sub(r"\s+", " ", text).strip(),
            **({"aliases": aliases} if aliases else {}),
            "affected": affected,
            "changelog": line,
            "review": {"state": "backfilled", "notes": notes},
        }
        with open(os.path.join(outdir, rid + ".json"), "w", encoding="utf-8") as f:
            json.dump(r, f, indent=1, ensure_ascii=False)
            f.write("\n")
    print("# released Xo versions (CHANGELOG sections), newest first")
    for v in releases:
        print(v)
    print(f"backfill: {len(found)} reports in {outdir}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
