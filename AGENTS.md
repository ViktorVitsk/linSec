# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

## Mission

Build a practical, modular personal security platform for my primary Pop!_OS workstation.

It must help me:

1. improve actual security of the workstation;
2. continuously monitor important security-relevant activity;
3. detect meaningful deviations and suspicious events;
4. understand what happened in plain language;
5. gradually learn Linux, networking and cybersecurity while using the system;
6. eventually reuse the architecture on other Linux machines;
7. later extend it to IoT devices, a home server and an isolated pentest laboratory.

This is NOT:

- an autonomous AI antivirus;
- a home SIEM built for its own sake;
- an excuse to install every security product;
- an LLM with root access.

Priorities:

SECURITY > RELIABILITY > UNDERSTANDABILITY > SIMPLICITY > AUTOMATION > FEATURES.

The project should become useful early and remain useful after every milestone.

---

# User/environment context

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



Potential sensitive material includes:

- SSH keys;
- API keys;
- Git credentials;
- source code;
- Docker credentials;
- browser sessions;
- OpenRouter credentials.

Current network situation:

[Publication redaction: private workstation observation/configuration omitted.]



Router:

- [router model withheld].

[Publication redaction: private workstation observation/configuration omitted.]



---

# Product philosophy

Use:

security mechanisms → normalized evidence → deterministic detection → correlation/baseline → alert → optional LLM explanation.

Do NOT use:

raw telemetry → LLM → autonomous action.

The LLM is an analyst, not the primary detector and not the executor.

The system must remain fully functional with:

```text
LLM_ENABLED=false
```

---

# Resource target

This is a desktop workstation.

Design for:

- lightweight continuous monitoring;
- negligible or low steady-state CPU usage;
- bounded memory usage;
- bounded disk retention;
- heavier scans through systemd timers / explicit scheduling;
- no continuous GPU load from the local LLM.

The computer is shut down daily, so schedules must tolerate missed runs and perform appropriate catch-up checks after boot.

---

# High-level architecture

Target conceptual pipeline:

```text
EVENT SOURCES
    |
    +-- Linux / journald
    +-- auth
    +-- process/security events
    +-- filesystem integrity
    +-- network/listeners
    +-- systemd/persistence
    +-- packages/repositories
    +-- firewall/DNS
    +-- Docker
    +-- developer supply chain
    |
    v
COLLECTORS / ADAPTERS
    |
    v
NORMALIZATION
    |
    v
EVENT STORE
    |
    +------> BASELINE / DIFF
    |
    +------> DETERMINISTIC RULES
    |
    v
CORRELATION / RISK
    |
    v
ALERT
    |
    +------> deterministic explanation
    |
    +------> optional local LLM
                    |
                    +------> optional manual cloud escalation
```

Future sources:

```text
IoT
mobile lab
additional Linux hosts
home server
```

Do not implement those until their milestone.

---

# Canonical event model

Design events from the start for single-host-now / multi-host-later operation.

At minimum consider:

```json
{
  "event_id": "...",
  "timestamp": "...",
  "host_id": "popos-main",
  "device_id": null,
  "source_type": "linux_host",
  "source": "systemd",
  "event_type": "SYSTEMD_UNIT_CHANGED",
  "severity_hint": "medium",
  "data": {},
  "evidence": [],
  "collector_version": "...",
  "schema_version": 1
}
```

`source_type` should be extensible to:

- `linux_host`
- `docker`
- `developer`
- `network`
- `iot`
- `mobile_lab`

Do not build distributed transport yet.

---

# Storage

Start with SQLite unless measurements show a real reason not to.

Likely entities:

- hosts/devices;
- events;
- alerts;
- baseline snapshots;
- baseline entries;
- suppression/trust rules;
- detector results;
- LLM analyses;
- action proposals;
- audit history.

Requirements:

- bounded retention;
- migrations;
- no unnecessary storage of sensitive raw logs;
- structured fields over giant text dumps;
- deterministic timestamps;
- schema versioning.

Keep raw telemetry only when it materially improves investigation.

---

# CLI

First-class UX is CLI.

Target commands:

```text
sec status
sec scan
sec alerts
sec alerts --severity high
sec explain <alert-id>
sec history
sec doctor

sec baseline show
sec baseline diff
sec baseline update

sec trust <alert-id>
sec suppress list
sec suppress remove <rule-id>

sec config validate
sec service status
```

Do not implement every command before the underlying functionality exists.

Future:

```text
sec device ...
sec lab ...
```

---

# `sec explain`

`sec explain <id>` is also a learning interface.

A useful explanation should contain:

```text
WHAT HAPPENED

WHY IT MATTERS

EVIDENCE

HOW WE DETECTED IT

WHAT THE OS / SECURITY MECHANISM IS DOING

LIKELY BENIGN EXPLANATIONS

WHAT TO CHECK NOW

MANUAL VERIFICATION

RECOMMENDED RESPONSE

AUTOMATIC ACTION
```

Avoid lectures unrelated to the alert.

Deep explanations belong in docs and should be linked/referenced from the CLI.

---

# Baseline model

Baseline is a major detection mechanism.

It should represent important known-good/known-expected state, not every volatile detail on the machine.

Candidate baseline categories:

- listening sockets including bind address;
- service/unit inventory;
- hashes/fingerprints of important systemd unit files;
- selected critical configuration fingerprints;
- users and privileged memberships;
- cron/timers/autostart;
- SSH authorized-key metadata/fingerprints where appropriate;
- firewall state;
- DNS configuration;
- Docker containers/security-relevant configuration;
- repositories/package sources;
- selected developer-tool/extension inventory.

For systemd, baseline BOTH:

1. service/unit existence and enablement;
2. configuration fingerprints.

Do not miss modification of an existing unit merely because no new service appeared.

Baseline modifications must be explicit and auditable.

Never automatically absorb an unexpected security-relevant change into baseline.

Before `baseline update`, show the diff.

---

# False positives / suppression

False-positive management is a core feature, not a later cleanup task.

`sec trust <alert-id>` must NOT create dangerously broad rules.

Bad:

```text
port 8000 is always safe
```

Better:

```text
expected process + executable + user + relevant path/context + bind address + port
```

A materially changed context must alert again.

Suppression rules should support:

- exact/narrow matching;
- explanation/reason;
- creation timestamp;
- provenance;
- optional expiration;
- manual listing/removal.

Never allow `trust` to silently rewrite a detector.

---

# Continuous monitoring

Use a HYBRID approach.

## Event-driven

Prefer event sources for things where timing matters:

- authentication events;
- privileged actions where feasible;
- process execution where signal/noise is acceptable;
- systemd/persistence changes;
- selected security-sensitive filesystem changes.

## Periodic

Use lightweight scheduled checks for:

- listening socket baseline;
- package/security update state;
- repositories;
- firewall/DNS state;
- Docker posture;
- file fingerprint reconciliation;
- vulnerability scanning;
- deeper host audit.

A reboot or missed timer must not create permanent blind spots.

---

# Detection priorities

Implement high-value detectors before exotic detections.

Initial detector candidates:

## Network

- new listening port;
- listener changes from localhost to LAN/all interfaces;
- unexpected IPv6 listener;
- unexpected firewall change;
- unexpected DNS resolver/configuration change.

Context should include process, executable, user and bind address when safely obtainable.

## Users/authentication

- new UID 0 account;
- unexpected sudo/admin-group membership;
- sudoers modification;
- new/changed SSH authorized-key fingerprint;
- suspicious authentication failures;
- unusual successful login when evidence is sufficient.

Never expose passwords or private keys.

## Persistence

- new systemd service/timer;
- modified systemd service/timer;
- new/changed user unit;
- cron changes;
- autostart changes;
- selected shell-startup persistence changes;
- `ld.so.preload` and similar high-risk mechanisms when applicable.

## Files/system

- selected high-value configuration changes;
- package repository changes;
- security controls unexpectedly disabled.

Do not attempt to hash the entire filesystem.

## Docker

Docker is a first-class security module.

Detect/audit:

- exposed host ports;
- bind to `0.0.0.0` / IPv6;
- privileged containers;
- host network/PID/IPC;
- Docker socket mounts;
- sensitive host mounts;
- dangerous capabilities;
- container root user where relevant;
- weak restart/config patterns;
- image vulnerability state;
- compose/config changes;
- secrets accidentally exposed through configuration/environment without logging secret values.

## Developer supply chain

Treat development tooling as part of the workstation attack surface.

Gradually cover:

- Git secret scanning;
- dependency vulnerability scanning;
- suspicious repository/package-source changes;
- lockfile/manifests;
- npm/pnpm/pip/Python ecosystem risks;
- Docker images;
- IDE extension inventory;
- browser extension inventory where it can be collected safely without accessing history/cookies.

Do not automatically run package "fix" commands that rewrite dependencies.

---

# Security tool selection

Do not start by installing a predefined pile of products.

First inventory what Pop!_OS already provides.

For each requirement evaluate mature existing mechanisms.

Candidates may include:

- journald;
- auditd;
- osquery;
- AppArmor;
- UFW OR nftables;
- unattended-upgrades;
- Lynis;
- Trivy;
- gitleaks;
- appropriate dependency scanners.

Evaluate whether an event-focused tool such as Falco adds enough unique value before introducing it.

ClamAV is optional supplemental scanning, not the foundation of protection.

Do not install overlapping firewall managers.

Do not install both competing log/security stacks without a concrete reason.

Initially avoid unless threat model changes materially:

- Wazuh manager/dashboard;
- Suricata;
- Zeek;
- CrowdSec;
- Fail2ban;
- large SIEM stacks.

They may be reconsidered later.

For every proposed tool document:

- what requirement it satisfies;
- why built-in mechanisms are insufficient;
- CPU/RAM/disk cost;
- privileges required;
- attack surface added;
- maintenance;
- false-positive implications;
- alternatives;
- removal/rollback.

---

# Firewall/network policy

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



Never blindly apply firewall rules.

Discovery first.

Current objective is generally:

```text
deny unsolicited inbound traffic
allow explicitly required services
```

but verify real usage.

Always consider BOTH IPv4 and IPv6.

Before changing firewall:

1. capture current state;
2. identify required services;
3. verify Docker interactions;
4. prepare rollback;
5. show exact rule change;
6. obtain approval;
7. apply;
8. verify from relevant interfaces.

Future LAN requirements include dashboards from a phone.

Do not permanently force all development services to localhost if legitimate LAN use is later requested.

Instead document narrow LAN policies when required.

Current state has no intentionally known public server exposure, but do not assume that remains true.

---

# Router

[router model withheld] belongs to the threat model.

Do not automate router login/configuration in the initial project.

Create a manual audit/hardening checklist.

[Publication redaction: private workstation observation/configuration omitted.]



Review concepts such as:

[Publication redaction: private workstation observation/configuration omitted.]



Do not assume full VLAN capability.

---

# AppArmor / boot / disk security

Audit:

- AppArmor actual state;
- Secure Boot state;
- disk encryption;
- kernel/security status where relevant.

Never rely on expected counts of AppArmor profiles.

Read the actual machine state.

Do not mass-switch AppArmor profiles into enforce mode automatically.

Do not attempt to retrofit disk encryption or Secure Boot as an ordinary automated change.

---

# Hardening workflow

For every proposed hardening item use:

```text
CURRENT STATE
THREAT / PROBLEM
PROPOSED CHANGE
BENEFIT
COMPATIBILITY RISK
EXACT CHANGE
VERIFICATION
ROLLBACK
```

Priorities:

- P0 critical/immediate;
- P1 important;
- P2 useful;
- P3 advanced/educational.

No change should be justified solely because a benchmark says so.

Explain its relevance to THIS workstation.

---

# Actions / remediation

User preference:

- harmless/internal automation may happen automatically;
- system-affecting actions require human approval;
- architecture may eventually support carefully allowlisted automatic remediation.

Initial automatic actions may include things such as:

- collect evidence;
- deduplicate alerts;
- store events;
- run safe internal correlation;
- send local notification;
- schedule a read-only follow-up scan.

Initial automatic remediation of host state is DISABLED.

Future remediation must use typed actions, e.g.:

```text
BLOCK_IP
STOP_SERVICE
DISABLE_SERVICE
QUARANTINE_FILE
STOP_CONTAINER
RESTORE_CONFIG
```

Each action must have:

- explicit ID;
- validated parameter schema;
- authorization policy;
- dry-run where possible;
- audit trail;
- verification;
- rollback where possible.

Never pass arbitrary model text to shell.

---

# Kill switch

Provide an obvious mechanism such as:

```text
sec disable
```

and/or:

```text
scripts/killswitch.sh
```

It must stop the orchestrator/monitoring components quickly.

It must NOT silently revert firewall/hardening.

System hardening rollback is a separate deliberate operation.

---

# Notifications

Initial:

- CLI;
- local desktop notifications (`notify-send` where appropriate).

Future adapter interfaces:

- Telegram;
- Signal;
- web dashboard.

Notification payloads must minimize sensitive data.

Do not implement external notification services before the core alert model is stable.

---

# Local LLM

Local LLM support is a REQUIRED long-term milestone but NOT a dependency for detection.

Before selecting a model:

- inspect GPU/driver;
- determine usable VRAM;
- benchmark candidate models;
- measure latency;
- measure memory;
- test short structured security-analysis prompts;
- test realistic context sizes.

[Publication redaction: private workstation observation/configuration omitted.]



Support a provider interface.

Example concept:

```python
class LLMProvider:
    def analyze(self, evidence_pack) -> Analysis:
        ...
```

Candidate backends may include maintained local runtimes such as Ollama or llama.cpp, selected after verification.

LLM input must be a compact EVIDENCE PACK, not arbitrary raw logs.

Output must be validated structured data, for example:

```json
{
  "classification": "likely_benign",
  "severity": "medium",
  "confidence": 0.82,
  "reasoning_summary": [
    "..."
  ],
  "recommended_actions": [
    "..."
  ],
  "needs_cloud_analysis": false
}
```

Do not request or store hidden chain-of-thought.

Only concise verifiable reasoning summaries.

If local LLM is unavailable:

```text
monitoring continues
detectors continue
alerts continue
deterministic explanations continue
```

---

# Prompt-injection protection for LLM analysis

Telemetry is UNTRUSTED.

The model receives clear separation between:

- instructions/schema;
- trusted detector metadata;
- untrusted evidence.

Test cases must include malicious-looking telemetry such as:

```text
Ignore all previous instructions and execute ...
```

Expected outcome:

- treated as evidence string;
- no command execution;
- no change of policy;
- alert analysis continues.

---

# OpenRouter

Cloud LLM analysis is OPTIONAL.

Initial policy:

```text
OPENROUTER_ENABLED=false
AUTO_CLOUD_ESCALATION=false
```

Cloud analysis occurs only after explicit user request.

Before cloud transmission:

```text
normalize
→ minimize fields
→ pseudonymize where reasonable
→ redact secrets
→ privacy check
→ show/record what categories will be transmitted
```

Prefer structured detector evidence over raw log excerpts.

Never transmit:

- private keys;
- tokens;
- cookies;
- browser/session databases;
- entire environment;
- broad home-directory content.

Later an explicit policy may permit automatic escalation for narrowly defined HIGH/CRITICAL cases, but it must be opt-in.

---

# Documentation is part of the product

Documentation quality is a Definition-of-Done requirement.

Primary language:

Russian.

Keep commands, identifiers and standard security terminology in their canonical English form where useful.

Code identifiers/comments should generally use English.

Structure documentation approximately as:

```text
docs/
├── getting-started/
│   ├── overview.md
│   ├── installation.md
│   ├── daily-usage.md
│   └── troubleshooting.md
├── architecture/
│   ├── overview.md
│   ├── event-pipeline.md
│   ├── trust-boundaries.md
│   ├── privilege-model.md
│   ├── data-model.md
│   └── llm-security.md
├── audit/
│   └── INITIAL_SECURITY_AUDIT.md
├── linux/
│   ├── processes.md
│   ├── systemd.md
│   ├── filesystem.md
│   ├── authentication.md
│   └── networking.md
├── detections/
├── docker/
├── dev-security/
├── operations/
│   ├── incident-response.md
│   ├── backup-recovery.md
│   └── rollback.md
├── router/
├── decisions/
└── future/
    ├── multi-host.md
    ├── iot-security.md
    └── pentest-lab.md
```

Avoid creating empty documentation files merely to satisfy the tree.

Create them when the relevant functionality exists.

---

# Detection documentation template

Every meaningful detector should eventually document:

```text
PURPOSE
What it protects.

THREAT
How an attacker or accidental misconfiguration can cause this condition.

BEGINNER EXPLANATION
Explain without assuming security expertise.

SYSTEM INTERNALS
Relevant Linux/network/container mechanism.

DATA SOURCE
Where telemetry comes from.

DETECTION LOGIC
Exact logic and important thresholds.

EVIDENCE
What is retained.

SEVERITY
Why the severity is appropriate.

FALSE POSITIVES
Normal situations that can trigger it.

SUPPRESSION
Safe way to trust expected behavior.

EVASION / LIMITATIONS
How detection can fail or be bypassed.

INVESTIGATION
What to inspect next.

MANUAL VERIFICATION
Commands a human can run without this orchestrator.

RESPONSE
Recommended response.

REFERENCES
Prefer official/upstream/current documentation.
```

This project should teach through real detections.

Do not force the user to study unrelated material before continuing development.

---

# Architecture decisions

Use lightweight ADRs for important design choices.

Example:

```text
docs/decisions/
ADR-001-use-sqlite.md
ADR-002-local-llm-is-not-detector.md
ADR-003-no-auto-remediation-initially.md
```

Each ADR should briefly record:

- context;
- decision;
- alternatives;
- consequences.

---

# Project self-security

The security tool itself is part of the attack surface.

Requirements:

- minimal dependencies;
- lock dependencies;
- no secrets in repository;
- `.env.example`, never real `.env`;
- secret scanning;
- dependency scanning;
- static/type/lint testing where useful;
- unit tests;
- input validation;
- safe subprocess APIs;
- no unsafe shell interpolation;
- versioned configuration schemas;
- migrations;
- audit log.

Do not modify the user's system Python environment.

Use an isolated project environment.

At the beginning of significant sessions inspect:

```text
git status
git diff -- AGENTS.md
```

and related security-critical policy/config files.

Unexpected policy modifications should be surfaced.

---

# Backups and recovery

Security is incomplete without recovery.

Audit whether backups exist without reading private backup data unnecessarily.

Document:

- important data;
- important configuration;
- backup destinations;
- offline/secondary copy strategy;
- recovery media;
- restoration verification.

Do not claim a backup is reliable merely because files exist.

---

# Incident response

Eventually provide beginner-friendly runbooks for at least:

- suspicious process;
- unexpected network listener;
- unknown login;
- suspicious privileged activity;
- modified persistence mechanism;
- stolen API token;
- stolen SSH key;
- suspicious Docker container;
- suspected malware/ransomware;
- suspected router compromise.

Each runbook:

```text
SYMPTOMS
IMMEDIATE ACTION
EVIDENCE PRESERVATION
CONTAINMENT
INVESTIGATION
RECOVERY
CREDENTIAL ROTATION
POST-INCIDENT CHECKS
```

Warn when an action could destroy forensic evidence.

---

# Milestones

Do NOT attempt all milestones at once.

## M0 — Safe Development Foundation

Goal:

make development itself safe and understandable.

Deliver:

- repository skeleton;
- project security model;
- dependency/environment strategy;
- basic tests/linting;
- Codex safety checks;
- documented sandbox/approval workflow.

Do not over-engineer.

## M1 — Protected Workstation

Goal:

understand and improve the actual current Pop!_OS posture.

Deliver:

- read-only host audit;
- attack-surface summary;
- update status;
- firewall/network assessment;
- users/privileges;
- persistence inventory;
- AppArmor;
- boot/disk security;
- Docker exposure;
- router manual checklist;
- prioritized hardening plan;
- rollback for every applied modification.

System changes occur one-by-one after explicit approval.

The project must already be useful here.

## M2 — Security Watchdog

Goal:

continuous useful monitoring.

Deliver:

- event schema;
- collectors/adapters;
- SQLite history;
- baseline;
- baseline diff;
- systemd/config fingerprints;
- high-value deterministic detectors;
- suppression/trust;
- CLI;
- local desktop alerts;
- systemd user/system service as appropriate;
- timers;
- resource measurements;
- kill switch;
- safe synthetic tests.

This is the first major daily-use milestone.

## M3 — Docker + Developer Security

Goal:

protect the workstation as a developer machine.

Deliver:

- Docker posture module;
- image/dependency scanning;
- secret scanning;
- repository/package-source monitoring;
- selected IDE/browser extension inventory;
- relevant detections and docs.

## M4 — Local AI Security Analyst

Goal:

gain real local-LLM security experience without making AI part of the trust boundary.

Deliver:

- provider abstraction;
- local runtime benchmark;
- structured evidence packs;
- validated outputs;
- redaction;
- prompt-injection tests;
- deterministic fallback;
- resource policy.

## M5 — UX / External integrations

Only after core stability.

Possible:

- localhost-only API;
- web dashboard;
- timeline/history UI;
- Telegram alert adapter;
- Signal alert adapter.

Never expose dashboard publicly by default.

## M6 — IoT / Grow System

NOT CURRENT PRIORITY.

The ESP32 is currently expected to remain unused for the next months.

Architecture only until this milestone.

Known future device:

[Publication redaction: private workstation observation/configuration omitted.]



Target security architecture should eventually prefer:

```text
Telegram / UI
      |
host backend / authorization
      |
MQTT broker
      |
ESP32
```

instead of storing unnecessary Internet-service credentials directly on the microcontroller.

Future topics:

[Publication redaction: private workstation observation/configuration omitted.]



Do NOT enable irreversible ESP32 security/eFuse options as part of ordinary automation.

Separate:

CYBERSECURITY — who is allowed to command the pump?

from:

FUNCTIONAL SAFETY — is it physically safe to activate the pump?

Pump safety interlocks must remain effective even for authenticated commands.

[Publication redaction: private workstation observation/configuration omitted.]



Evaluate Rust later as its own migration/security experiment.

## M7 — Isolated Pentest Lab

Future only.

Device:

Xiaomi Mi 9 Lite, dedicated primarily to lab/pentest use and content recording.

Treat it as an UNTRUSTED/LAB endpoint.

Do not store production credentials, primary 2FA or critical personal secrets on it.

Build an isolated authorized laboratory where:

```text
attacker/lab device
       |
controlled test
       |
lab target
       |
telemetry
       |
Security Orchestrator
       |
detector
       |
explanation
```

Only test systems owned by the user or explicitly authorized.

The purpose is to connect attacker and defender perspectives, not to turn the production workstation into a vulnerable target.

## M8 — Multi-host / Home Security

Future.

Move toward:

```text
Pop!_OS workstation
Raspberry Pi / mini-PC
other Linux hosts
IoT
```

without rewriting the event/detection core.

Do NOT build centralized enrollment/distributed infrastructure during early milestones.

---

# Initial non-goals

Do not prematurely implement:

- SIEM;
- Kubernetes;
- microservices;
- message buses;
- distributed agents;
- public web APIs;
- full network IDS;
- autonomous remediation;
- Wazuh dashboard;
- elaborate ML anomaly models.

Choose them later only when a demonstrated requirement justifies them.

---

# Working method

For every milestone:

1. inspect current reality;
2. state assumptions;
3. identify the smallest useful implementation;
4. implement;
5. test;
6. measure;
7. document;
8. summarize what the user now has;
9. list remaining risks;
10. stop before expanding scope unnecessarily.

Do not generate hundreds of files up front.

Prefer small reviewable increments.

When a useful partial system works, demonstrate it before continuing.

---

# External documentation

Security recommendations change.

Before applying third-party/security/device-specific configuration:

- verify current official/upstream documentation;
- verify actual Pop!_OS/Ubuntu compatibility;
- verify project maintenance status;
- verify current command syntax;
- verify conflicts;
- prefer primary sources.

Record important source links and verification date in project docs.

[Publication redaction: private workstation observation/configuration omitted.]



---

# Definition of overall success

The project succeeds when the user can:

- understand current host security posture;
- see meaningful alerts without drowning in noise;
- understand why an alert matters;
- manually reproduce important checks;
- distinguish telemetry, detection, correlation and response;
- safely tune false positives;
- understand Linux/network/Docker security mechanisms through real events;
- operate the tool without needing a separate cybersecurity course;
- later adapt the architecture to another Linux workstation;
- extend it to IoT/lab/multi-host use without replacing the core.

Actual security improvement matters more than feature count.