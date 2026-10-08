# Sanitized publication review — 2026-10-08

**Security verdict: READY for owner review of this separate copy. Nothing has been published.** This report supersedes the earlier disclosure blocker for this sanitized branch only. The originals remain private and are not approved for transfer. License selection remains an owner's reuse decision.

## History and attribution

| Check | Result |
| --- | --- |
| Publication branch | `refs/heads/main` only |
| Source commits → preserved historical commits | 39 → 39 |
| New publication documentation commit | +1; final total 40 |
| Parents, order, author/committer names and timestamps/time zones | Preserved for every mapped commit |
| Historical messages | All preserved |
| Commits made empty by withholding private-only content | 4, retained in sequence |
| Author and committer email | Owner-confirmed GitHub noreply identity on every commit |
| Original object IDs | Rewritten; old IDs quoted in dated documents/messages refer to private source history |

Git's official branch-only bundle/clone workflow and git-filter-repo v2.47.0 were used. No squash, fabricated author, backdated publication commit, test execution, system change or push was performed. Mapping/procedural records and unsanitized source bundles are private and outside this publication copy. Original ASCP WIP and all original refs were excluded.

## Withheld data and evidence cost

Throughout reachable history, the copy removes or aliases personal email, local account/home paths, real host/sensor/organization and VM labels, private network/MAC/UUID identifiers, router model, exact workstation inventory/security posture, installed credentials/authorization/network settings and actionable private host findings. No replacement observation is presented as a real measurement. Public aliases such as `/workspace/ASCP`, `/workspace/linSec`, `/home/portfolio`, `/home/sandbox` and `publication-sandbox` are templates.

All `src/`, tests, example configurations and dependency lock files are byte-identical throughout the mapped history. The only non-documentation substitution is a private home-path reference in `scripts/check_m2c_package.py`. Synthetic fixtures, including synthetic private-network addresses, remain: they are test inputs, not workstation disclosures.

The workstation audit, firewall plan and owner/recovery decision record retain methods, scope, section structure and explicit omission notices, but not exact observations, target policies or actionable private findings. Some host-specific verification evidence was intentionally withheld. The public history consequently cannot independently prove those private host changes or recovery conditions; unknowns and historical software test results are not converted into new PASS claims.

## Checks

Official [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), archive SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`, verified against official release checksums. Built-in rules, `--redact=100`, inline allow comments disabled, no custom config/baseline/ignore list. Git scope: `--full-history --root -m HEAD`; current directory and commit metadata were scanned separately. Raw redacted reports remain private.

History, directory snapshot and commit-metadata scans each returned exit 0, zero findings. The explicit synthetic invalid-credential fixture remains unchanged; it was not reported as a credential by Gitleaks.

Known private-token checks cover all reachable text blobs and commit metadata, with synthetic test data distinguished from actual host observations. The cleaned copies contain no known personal email or private deployment identifiers. Static Git checks verify commit topology/attribution, preserved tracked paths and file modes, key project files, syntax/JSON and current local documentation links. Git integrity/reachability checks and a final fresh branch-only clone exclude service refs, replacement/backup refs, old commits, unreachable objects, reflog retention of old history, alternates and private archives. No runtime or project acceptance tests were repeated.

## Remaining public information and limits

Author names, the GitHub noreply identity, development dates/time zones and substantive messages remain public by design. So do software architecture, generic security defaults/resource limits, historical tool/provider/model names and source/artifact fingerprints. An observer can learn how these prototypes were built and identify documented limitations. These are engineering evidence, not a map or attestation of the owner's current installation. Secret scanning and a bounded metadata review cannot certify absence of every possible disclosure. Cleaning this copy cannot retract any earlier publication or external clone of the originals.

## License recommendation

Recommend [MIT](https://opensource.org/license/mit) for this archived engineering portfolio's original code/docs, provided the owner has rights to grant that license. Keep notices for copied third-party portions; AI assistance alone does not establish ownership. No vendored dependency/model tree or submodule was found in the selected history. Tool invocations and external dependencies retain their own licenses; a project license does not relicense them. [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) is an alternative when an explicit contributor patent grant is wanted. No LICENSE was added without the owner's selection.

## Transfer boundary — instructions only, not executed

Use this cleaned copy and a new empty GitHub repository after separate owner approval. Verify the final reviewed HEAD against the external local review report before transfer. The explicit branch refspec sends its cleaned ancestor history and reachable trees/blobs; it does not select unrelated refs. [Git push reference](https://git-scm.com/docs/git-push).

```sh
# Template only; replace APPROVED_EMPTY_REPOSITORY_URL after owner approval.
git -c push.followTags=false -c push.recurseSubmodules=no push --no-follow-tags APPROVED_EMPTY_REPOSITORY_URL refs/heads/main:refs/heads/main
```

Do not use `--all`, `--mirror`, `--tags`, wildcard refspecs, or transfer original repositories/bundles/archives. Only the cleaned main branch was included. These are independent Git repositories with no remotes and no links to original object stores.
