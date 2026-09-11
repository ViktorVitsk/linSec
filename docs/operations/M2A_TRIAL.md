# M2a Operational Trial

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

## Trial status

Started: 2026-09-11
Duration target: 7 days
Status: in progress

## Start state

- baseline revision: 1
- active alerts: 0
- pending notifications: 0
- LLM: disabled
- host permissions/security settings changed: no

### Coverage

- tcp4: ok, context may be incomplete
- tcp6: ok, context may be incomplete
- udp4: ok, context may be incomplete
- udp6: ok, context may be incomplete
- systemd_system: partial / access_or_io
- systemd_user: ok
- accounts: ok
- persistence: ok

### Known coverage gaps

- systemd-timesyncd dangling unit links
- root-owned netplan-ovs-cleanup runtime unit unreadable by dev
- process context unavailable for some privileged/foreign sockets

These limitations are intentionally not resolved by elevating watchdog privileges.

## Real-host acceptance findings

- Initial baseline on legitimate partial source exposed an M2a defect.
- Baseline semantics were corrected to support reviewed partial snapshots.
- Partial snapshots do not create false removals.
- unavailable/stale/config mismatch/storage failures still block baseline.
- SQLite schema migrated v1 → v2.
- Regression suite: 68 tests passing.

## Trial observations

### Day 1
...

### Day 2
...

## Metrics

[Publication redaction: private workstation observation/configuration omitted.]



## Final assessment

Actual trial observation start: 2026-09-11T17:11:21.752213+03:00
Planned trial end: 2026-09-18T17:11:21.752213+03:00

Initial runtime checkpoint:

- monitor PID=[withheld]
- monitor mode: `sec monitor --iterations 0`
- monitor instances observed: 1
- cycle interval observed: approximately 5 minutes
- active/pending notifications at start: 0
- second monitor cycle: pending_notifications=0
- health: degraded
- expected degraded source: `systemd_system=partial`, reason=`access_or_io`
- TCP/UDP sources: collection successful; some process context remains unavailable (`context_missing`) as expected
- baseline revision: 1
- baseline scope changed: false
- collector configuration changed: false
- storage: 708608 bytes (692 KiB)
- storage budget: 536870912 bytes (512 MiB)
- last storage write failed: false
- LLM enabled: false
- orchestrator disabled: false
- `sec status` exit code: 2, expected because of known degraded/partial coverage