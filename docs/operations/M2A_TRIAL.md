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



## Initial operational soak — 2026-09-11 → 2026-09-12

The first M2a operational soak was intentionally ended after approximately one day of normal workstation use.

This run is **not** considered completion of the originally planned 7-day operational trial.

The purpose of this first soak was to obtain an initial real-world stability/resource checkpoint while development continued. The full 7-day operational soak is deferred until a later integration/release-candidate stage, when its results will characterize a substantially more complete system.

### Run

Monitor command:

`sec monitor --iterations 0`

Process:

* PID: `95568`
* started: `2026-09-11 17:11:18 +03:00`
* final checkpoint: `2026-09-12T16:49:26+03:00`
* observed elapsed runtime at final checkpoint: `23:38:07`
* foreground monitor instances observed: `1`
* foreground state at final checkpoint: `true`
* orchestrator disabled: `false`

The monitor survived at least one desktop lock/sleep-like transition and continued operating afterwards. This observation does not by itself prove that the host entered a kernel/system suspend state.

### Source health at final checkpoint

Expected source state remained stable:

* `tcp4`: `ok`, `reason=context_missing`
* `tcp6`: `ok`, `reason=context_missing`
* `udp4`: `ok`, `reason=context_missing`
* `udp6`: `ok`, `reason=context_missing`
* `systemd_system`: `partial`, `reason=access_or_io`
* `systemd_user`: `ok`
* `accounts`: `ok`
* `persistence`: `ok`

The known `systemd_system=partial/access_or_io` condition remained expected and was not treated as a defect.

At the final checkpoint:

* `health=degraded`
* `stale=false` for all reported sources
* `baseline_revision=1`
* `baseline_scope_changed=false`
* `config_changed=false`
* `last_storage_write_failed=false`
* `llm_enabled=false`
* `sec status` exit code was `2`, as expected for the known degraded/partial state.

No privilege escalation or host-security configuration change was performed to obtain a healthier status.

### Resource observations

Initial checkpoint:

[Publication redaction: private workstation observation/configuration omitted.]



Final checkpoint after `23:38:07`:

[Publication redaction: private workstation observation/configuration omitted.]



Observed change over the run:

[Publication redaction: private workstation observation/configuration omitted.]



These are endpoint samples, not proof of average CPU/memory usage or a long-term growth rate.

Storage remained far below the configured budget:

* final storage: `999424 bytes`
* storage budget: `536870912 bytes`

No storage-write failure was reported.

### Assessment

The approximately 24-hour foreground run did not reveal an operational blocker.

Observed behaviour was consistent with the accepted M2a model:

* the monitor remained alive;
* periodic collection continued;
* known partial coverage remained stable;
* baseline/config scope did not change;
* no storage failure was reported;
* memory and SQLite growth remained modest during this limited observation window.

This run is sufficient as an **initial operational soak**, but not as evidence for multi-day stability, reboot recovery, long-term database growth, or completion of the planned 7-day trial.

### Trial sequencing decision

The originally planned 7-day operational trial is deferred rather than cancelled.

It will be performed at a later integration/release-candidate stage, after current development and milestone acceptance work is substantially complete.

Rationale:

* running the full soak in the middle of active development would characterize an intermediate build;
* later milestones can intentionally change runtime/resource behaviour;
* the final soak is more valuable when performed against a version close to normal long-term operation;
* ordinary suspend/reboot/logout behaviour should be included in that later operational trial rather than requiring 168 hours of uninterrupted uptime.

The initial M2a soak therefore does **not** block continued M2c acceptance or subsequent development.
