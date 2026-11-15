# vulndb

The reports behind [vuln.xolang.org](https://vuln.xolang.org), the
vulnerability database of [Xo](https://xolang.dev): std (versioned by Xo
release), the `xo` toolchain, and modules published through
proxy.xolang.org. The design is decision 0647 in
[xo-lang/xo](https://github.com/xo-lang/xo/blob/main/knowledgebase/decisions/0647-vulnerability-database.md).
`xo vuln` reads the published database.

## Layout

- `data/reports/XO-YYYY-NNNN.json`: one report per entry (the schema is in
  `vulndb/report.py`): module (`std`, `toolchain` or a module path), range
  (`introduced` and `fixed`, or `last_affected` while no release has the
  fix), the std modules or packages and symbols affected, the backends and
  platforms when not all, aliases (CVE, GO), the CHANGELOG line.
- `data/releases.txt`: the released Xo versions a `fixed` may name.
- `vulndb/gen.py`: writes the OSV 1.6 entries (`ID/XO-YYYY-NNNN.json`), the
  indexes (`index/db.json`, `index/modules.json`, `index/vulns.json`, as
  vuln.go.dev), `vulndb.zip` and the root page.
- `scripts/backfill_changelog.py`: the one-time backfill from xo-lang/xo's
  CHANGELOG `Security` lines (each report keeps `review.state:
  backfilled` until a reviewer checks its range and symbols).
- `scripts/publish-r2.sh`: the upload, entries first and `index/db.json` last.

## Running it

    python3 -E -s -m unittest discover -s tests -t .
    python3 -E -s -m vulndb.gen /tmp/vulndb-out
    XO_VULNDB=file:///tmp/vulndb-out xo vuln ./...

Standard library only. `.github/workflows/build.yml` runs the tests and the
generator on every push and pull request, and publishes from main.

## Adding a report

One file per vulnerability, the next free id of the year, the range from
the release that fixed it, the CHANGELOG line it shipped with. Report a
vulnerability privately first: [SECURITY.md](https://github.com/xo-lang/xo/blob/main/SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
