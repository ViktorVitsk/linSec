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

Pending.