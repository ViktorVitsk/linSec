# Archive and publication review — 2026-10-08

**Disposition: documentation prepared; publication pending owner decisions.**
This is a bounded local publication review. It does not restart linSec development,
monitoring, AI acceptance or the operational trial. No push, visibility change,
history rewrite, service launch, credential change or deletion was performed.

## Scope and method

Starting branch: `main`, `05ac126626880410a9336e35628ca723a1cd2a1b`, with a clean
working tree, 95 tracked paths and 37 reachable commits. All locally available
refs (including cached `origin` refs) were inventoried: 285 distinct blobs, all text
and below 2 MiB, plus commit metadata. Remote contents and visibility were not
queried; a cached remote ref does not establish present GitHub state.

Read-only Git inventory/history commands and the existing `scripts/check_m0.py`
were used. A temporary Python/regex pass searched tracked working-tree text and
reachable blobs/commit text for private-key headers, common provider-token prefixes,
JWT shapes, credential-bearing URLs and quoted credential assignments. Home paths,
private IPv4 addresses, MAC-like strings and email metadata were also located.
Matched credential values were not included in this report.

Gitleaks, TruffleHog and detect-secrets were unavailable on PATH; no scanner was
installed or downloaded. This limited search is **not equivalent to a maintained
secret scanner**. Ignored runtime files, reflogs/unreachable objects, remote-only
history and GitHub account/settings were outside scope. No absence-of-secrets
certification is claimed.

## Findings and minimal next decisions

| Finding | Evidence location / scope | Minimal safe response before publication |
| --- | --- | --- |
| No confirmed credential in inspected text | One quoted credential candidate in `tests/test_investigation.py`, present in three historical blob versions, is an explicit synthetic invalid-config fixture. | Keep the test. Run a maintained scanner with redacted output against the intended publication refs before pushing; do not blanket-allowlist tests. Revoke/rotate any real credential found in a later scan. |
| Real workstation/network metadata in tracked history | `docs/audit/INITIAL_SECURITY_AUDIT.md` contains dated network, privilege, software and persistence inventory; `docs/architecture/INITIAL_THREAT_MODEL.md` includes network context. Host paths also appear in operational docs and package-inspection tooling. | Owner must decide whether these details can be public. Preserve originals. If disclosure is unacceptable, keep this history private and agree a separate publication/redaction strategy; changing only HEAD does not remove earlier copies. |
| Synthetic examples need different treatment from host evidence | Private-address/path matches also occur in `tests/test_local_ui.py` and `tests/test_watchdog.py`. | These fixture matches are not themselves evidence of leaked workstation data. Do not remove useful negative tests to obtain an empty search result. |
| Git identity is disclosed by history | One author/committer email identity, not a GitHub noreply address; value omitted here. | Confirm intended public attribution. No identity rewrite or global Git configuration change was performed. |
| No tracked runtime/database/log/private-key paths found in inspected history | Git path inventory and ignore behavior; private runtime data remains local. | Publish only explicitly reviewed refs/files. Do not upload a whole working-directory archive containing ignored `runtime/` data. |
| Distribution license not selected | No repository LICENSE file or selected project license in metadata. | Owner to choose intended reuse terms and review applicable notices; no license was added on the owner's behalf. |

These are privacy and publication concerns, not a new host-security verdict.
Historical firewall or acceptance reports do not establish the current machine's
state. Reusing this code on another host requires its own scoped verification.

## Preparation and checks

- English README maps functionality, architecture, significant decisions and dated
  acceptance to source/tests; Russian summary remains available. Agent involvement
  and attribution limits are explicit.
- Archive notices in AGENTS and ROADMAP supersede older instructions to resume trial
  or implementation. The source, tests, detailed Russian records and Git history
  are preserved; no unrelated working-tree changes existed at the start.
- Safe CLI demo checked against a temporary `git archive HEAD` export with the
  already available Python 3.13.15 interpreter and `PYTHONPATH=src`: exit 0,
  `synthetic_only`, alerts 5 → 5 → 7 for initial/repeated/changed evidence,
  `host_collection=false`, `system_changes=false`. The database was separate
  temporary synthetic state. No host collectors, provider, Docker or HTTP server ran.
- Existing repository hygiene and `git diff --check`: PASS. Checked 184 local
  Markdown links (including fragment targets), with no missing destinations/anchors. Full synthetic suites,
  remote CI, host acceptance and benchmarks were not repeated.
- Byte comparisons against the clean starting HEAD confirm that
  source/tests/configuration and existing evidence documents did not change. Only explicit documentation paths
  enter the local portfolio commit.

The README's test counts and acceptance results come from dated records and are
not presented as new tests. Historical upstream links/product comparisons were
not re-researched; new README links point to repository evidence.
