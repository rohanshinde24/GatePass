# GatePass

Standalone event admission for an existing CSV guest list. Issue QR tickets, give staff scoped scanners, and recover interrupted check-ins without recording a second admission.

Requires macOS 14+, Swift 6.2, and PostgreSQL command-line tools.

```sh
swift build -j 4
sh scripts/dev-db.sh
.build/debug/GatePassServer serve --hostname 127.0.0.1 --port 8788
```

In another terminal, run `.build/debug/GatePassAdmin --help`. The workflow is `event-create` → `roster-import` → `device-create` → `scan` → `attendance-export`. Synthetic input is in `Fixtures/attendees.csv`.

Run `swift test -j 4` and, with ports 8788/8789 free, `python3 scripts/e2e.py` to exercise the complete workflow against PostgreSQL.

The optional iPhone scanner lives in `ios/GatePassScanner`. Generate its Xcode project with `xcodegen generate --spec ios/GatePassScanner/project.yml`, then select the `GatePassScanner` scheme.

Admission requires a connection. The development database uses loopback-only trust authentication; use database credentials and trusted HTTPS before a real event. Never share staff setup files or ticket archives publicly.
