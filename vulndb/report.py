"""Reports: one JSON file per entry under data/reports (decision 0647 of
xo-lang/xo). Standard library only.

A report:

    {
      "id": "XO-2026-0001",
      "published": "2026-11-14",            # the release that fixed it, or the day it was filed
      "modified": "2026-11-15",
      "summary": "one line",
      "details": "the CHANGELOG line, or more",
      "aliases": ["CVE-...", "GO-..."],
      "affected": [
        {
          "module": "std",                  # std, toolchain, or a module path
          "introduced": "0",                # "0" for every release before fixed
          "fixed": "0.51.1",                # a released version, or absent
          "last_affected": "0.51.1",        # instead of fixed while no release has the fix
          "imports": [{"path": "std/png", "symbols": ["decode"]}],
          "backends": ["native"],           # absent: every backend
          "platforms": ["macOS"]            # absent: every platform
        }
      ],
      "references": [{"type": "FIX", "url": "https://github.com/xo-lang/xo/commit/..."}],
      "changelog": "the CHANGELOG line as written",
      "credits": []
    }
"""

import json
import os
import re

ID_RE = re.compile(r"^XO-\d{4}-\d{4}$")
VERSION_RE = re.compile(r"^(0|\d+\.\d+\.\d+)$")
MODULE_RE = re.compile(r"^(std|toolchain|[a-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9._~-]+)+)$")
BACKENDS = {"native", "llvm", "go", "wasm"}
REF_TYPES = {"ADVISORY", "ARTICLE", "DETECTION", "DISCUSSION", "REPORT", "FIX", "INTRODUCED", "PACKAGE", "EVIDENCE", "WEB"}


def version_key(v):
    if v == "0":
        return (0, 0, 0)
    return tuple(int(x) for x in v.split("."))


class ReportError(Exception):
    pass


def check(r, released=None):
    """Raise ReportError for the first problem in report r. released, a set
    of version strings, when given, must hold every fixed version."""
    for k in ("id", "published", "modified", "summary", "details", "affected"):
        if k not in r:
            raise ReportError(f"{r.get('id', '?')}: no {k}")
    if not ID_RE.match(r["id"]):
        raise ReportError(f"{r['id']}: id is not XO-YYYY-NNNN")
    for k in ("published", "modified"):
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", r[k]):
            raise ReportError(f"{r['id']}: {k} {r[k]!r} is not YYYY-MM-DD")
    if r["modified"] < r["published"]:
        raise ReportError(f"{r['id']}: modified before published")
    if not r["summary"].strip() or "\n" in r["summary"]:
        raise ReportError(f"{r['id']}: summary must be one non-empty line")
    if not r["affected"]:
        raise ReportError(f"{r['id']}: no affected module")
    for a in r["affected"]:
        m = a.get("module", "")
        if not MODULE_RE.match(m):
            raise ReportError(f"{r['id']}: module {m!r}")
        intro = a.get("introduced", "")
        if not VERSION_RE.match(intro):
            raise ReportError(f"{r['id']}: introduced {intro!r}")
        fixed, last = a.get("fixed"), a.get("last_affected")
        if (fixed is None) == (last is None):
            raise ReportError(f"{r['id']}: give one of fixed and last_affected")
        end = fixed or last
        if not VERSION_RE.match(end) or end == "0":
            raise ReportError(f"{r['id']}: end version {end!r}")
        if fixed and version_key(fixed) <= version_key(intro):
            raise ReportError(f"{r['id']}: fixed {fixed} is not after introduced {intro}")
        if last and version_key(last) < version_key(intro):
            raise ReportError(f"{r['id']}: last_affected {last} is before introduced {intro}")
        if released is not None and fixed and fixed not in released:
            raise ReportError(f"{r['id']}: fixed {fixed} is not a release")
        for b in a.get("backends", []):
            if b not in BACKENDS:
                raise ReportError(f"{r['id']}: backend {b!r}")
        for imp in a.get("imports", []):
            p = imp.get("path", "")
            if m == "std" and not p.startswith("std/"):
                raise ReportError(f"{r['id']}: std import {p!r}")
            if not isinstance(imp.get("symbols", []), list):
                raise ReportError(f"{r['id']}: symbols must be a list")
    for ref in r.get("references", []):
        if ref.get("type") not in REF_TYPES or not ref.get("url", "").startswith("https://"):
            raise ReportError(f"{r['id']}: reference {ref}")


def load(dirpath):
    out = []
    for name in sorted(os.listdir(dirpath)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(dirpath, name), encoding="utf-8") as f:
            r = json.load(f)
        if name != r.get("id", "") + ".json":
            raise ReportError(f"{name}: file name does not match id {r.get('id')}")
        out.append(r)
    ids = [r["id"] for r in out]
    if len(ids) != len(set(ids)):
        raise ReportError("duplicate ids")
    return out
