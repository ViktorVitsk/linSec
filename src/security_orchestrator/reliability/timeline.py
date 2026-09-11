"""Opt-in minimized investigation timeline; never persist prompts or credentials."""

from ..investigation.contracts import integer, require
from ..model import now
import re

KINDS = {
    "trigger",
    "evidence_pack",
    "privacy_preview",
    "privacy_accepted",
    "privacy_rejected",
    "provider_request",
    "provider_result",
    "operation_request",
    "operation_accepted",
    "operation_rejected",
    "evidence_acquired",
    "fallback",
    "stop",
}
CODES = {
    "none",
    "metadata_aliases_v1",
    "validated",
    "rejected",
    "llm_disabled",
    "completed",
    "analysis_failed_contents_omitted",
    "privacy_approval_required",
    "step_limit",
    "token_budget_exhausted",
    "cost_budget_exhausted",
    "time_budget_exhausted",
    "provider_usage_exceeds_reserve",
    "unknown_evidence_id",
    "forbidden_operation",
    "operation_scope",
    "repeated_operation",
    "evidence_changed_new_preview_required",
    "cloud_disabled",
    "local_runtime_requires_no_cloud_verification",
}
OPERATIONS = {"", "get_alert", "get_observation", "compare_baseline", "lookup_runbook", "history"}


class Timeline:
    def __init__(self):
        self.entries: list[dict] = []

    def event(
        self,
        kind: str,
        code: str = "none",
        operation: str = "",
        step: int = 0,
        references: tuple[str, ...] = (),
    ) -> None:
        require(kind in KINDS and operation in OPERATIONS and integer(step, 0, 5))
        require(len(self.entries) < 64, "timeline_limit")
        self.entries.append(
            {
                "at": now(),
                "kind": kind,
                "code": code if code in CODES else "analysis_failed_contents_omitted",
                "operation": operation,
                "step": step,
                "references": list(references),
            }
        )

    def finish(self, result: dict) -> dict:
        mode = result.get("mode")
        reason = result.get("reason", "completed")
        if mode == "deterministic":
            self.event("fallback", reason)
        self.event("stop", reason)
        ledger = result.get("ledger", [])
        # Only numeric usage, fixed stages; no approval digests, model text or raw payloads.
        budgets = []
        for row in ledger[:5]:
            budgets.append(
                {
                    key: row.get(key, 0)
                    for key in (
                        "step",
                        "reserved_tokens",
                        "reserved_microusd",
                        "input_tokens",
                        "output_tokens",
                        "cost_microusd",
                    )
                }
            )
        record = {
            "schema_version": 1,
            "entries": self.entries,
            "budgets": budgets,
            "step_count": len(ledger),
            "mode": mode,
            "stop_reason": reason if reason in CODES else "analysis_failed_contents_omitted",
            "result_text": "omitted_privacy; inspect original CLI result locally",
        }
        validate_record(record)
        return record


def validate_record(record: dict) -> None:
    from ..investigation.evidence import timestamp

    require(
        isinstance(record, dict)
        and set(record)
        == {
            "schema_version",
            "entries",
            "budgets",
            "step_count",
            "mode",
            "stop_reason",
            "result_text",
        }
    )
    require(
        type(record["schema_version"]) is int
        and record["schema_version"] == 1
        and record["mode"] in {"deterministic", "ai_hypothesis_requires_human_review"}
    )
    require(record["stop_reason"] in CODES and integer(record["step_count"], 0, 5))
    require(record["result_text"] == "omitted_privacy; inspect original CLI result locally")
    require(isinstance(record["entries"], list) and len(record["entries"]) <= 64)
    for entry in record["entries"]:
        require(
            isinstance(entry, dict)
            and set(entry) == {"at", "kind", "code", "operation", "step", "references"}
        )
        timestamp(entry["at"])
        require(isinstance(entry["references"], list) and len(entry["references"]) <= 32)
        require(
            all(
                isinstance(ref, str)
                and re.fullmatch(
                    r"(?:(?:alert|snapshot):[1-9][0-9]{0,9}|runbook:(?:endpoint|file|unit|uid0|group):1)",
                    ref,
                )
                for ref in entry["references"]
            )
        )
        require(
            entry["kind"] in KINDS
            and entry["code"] in CODES
            and entry["operation"] in OPERATIONS
            and integer(entry["step"], 0, 5)
        )
    require(isinstance(record["budgets"], list) and len(record["budgets"]) <= 5)
    for budget in record["budgets"]:
        require(
            isinstance(budget, dict)
            and set(budget)
            == {
                "step",
                "reserved_tokens",
                "reserved_microusd",
                "input_tokens",
                "output_tokens",
                "cost_microusd",
            }
        )
        require(all(integer(v, 0, 10**12) for v in budget.values()))
