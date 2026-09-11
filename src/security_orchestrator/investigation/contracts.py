"""Small strict schemas, independent of M2a configuration and storage versions."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
import tomllib

from ..model import InvalidInput

VERSION = 1
PROMPT_VERSION = "m2b-1"
MAX_WIRE = 65536


def require(condition: bool, code: str = "invalid_analysis_contract") -> None:
    if not condition:
        raise InvalidInput(code)


def integer(value, low=0, high=2**31 - 1) -> bool:
    return type(value) is int and low <= value <= high


def strict_json(raw: str | bytes, limit: int = MAX_WIRE):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    try:
        require(isinstance(raw, (str, bytes)) and len(raw) <= limit)
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(depth <= 24 and nodes <= 8192)
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        raise InvalidInput("invalid_analysis_json_contents_omitted") from error


@dataclass(frozen=True)
class Settings:
    schema_version: int = VERSION
    llm_enabled: bool = False
    openrouter_enabled: bool = False
    provider: str = "disabled"
    model: str = ""
    allowed_providers: tuple[str, ...] = ()
    local_runtime_verified: bool = False
    max_steps: int = 1
    timeout_seconds: int = 30
    total_seconds: int = 120
    max_input_tokens: int = 24000
    max_output_tokens: int = 1024
    total_tokens: int = 32000
    budget_microusd: int = 0
    input_price_microusd_per_million: int = 0
    output_price_microusd_per_million: int = 0

    def validate(self):
        require(type(self.schema_version) is int and self.schema_version == VERSION)
        require(
            all(
                type(v) is bool
                for v in (
                    self.llm_enabled,
                    self.openrouter_enabled,
                    self.local_runtime_verified,
                )
            )
        )
        require(self.provider in ("disabled", "openrouter", "ollama"))
        for value, low, high in (
            (self.max_steps, 1, 5),
            (self.timeout_seconds, 1, 60),
            (self.total_seconds, 1, 300),
            (self.max_input_tokens, 1024, 64000),
            (self.max_output_tokens, 128, 4096),
            (self.total_tokens, 1024, 320000),
            (self.budget_microusd, 0, 10_000_000),
            (self.input_price_microusd_per_million, 0, 100_000_000),
            (self.output_price_microusd_per_million, 0, 100_000_000),
        ):
            require(integer(value, low, high), "invalid_ai_budget")
        require(isinstance(self.model, str) and len(self.model) <= 128)
        if self.provider != "disabled":
            require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", self.model)))
            require(".." not in self.model and "://" not in self.model)
        require(isinstance(self.allowed_providers, (tuple, list)))
        require(len(self.allowed_providers) <= 8)
        for name in self.allowed_providers:
            require(isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)))
        if self.provider == "openrouter":
            require(bool(self.allowed_providers), "cloud_requires_provider_allowlist")
            require(self.budget_microusd > 0, "cloud_requires_budget")
            require(self.input_price_microusd_per_million > 0)
            require(self.output_price_microusd_per_million > 0)
        if self.provider == "ollama":
            require("cloud" not in self.model.lower(), "local_model_required")

    def public(self):
        return asdict(self)


def load_settings(path: Path | None) -> Settings:
    if path is None:
        return Settings()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            raw = stream.read(16385)
        require(len(raw) <= 16384)
        settings = Settings(**tomllib.loads(raw.decode("utf-8")))
        settings.validate()
        return settings
    except (ValueError, OSError, TypeError) as error:
        raise InvalidInput("invalid_ai_config_contents_omitted") from error


TEXT_ARRAY = {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 1000}}
RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "kind",
        "summary",
        "hypotheses",
        "unknowns",
        "checks",
        "references",
        "operation",
        "arguments",
    ],
    "properties": {
        "kind": {"type": "string", "enum": ["answer", "operation"]},
        "summary": {"type": "string", "maxLength": 2000},
        "hypotheses": TEXT_ARRAY,
        "unknowns": TEXT_ARRAY,
        "checks": TEXT_ARRAY,
        "references": {
            "type": "array",
            "maxItems": 24,
            "items": {"type": "string", "maxLength": 64},
        },
        "operation": {
            "type": "string",
            "enum": [
                "",
                "get_alert",
                "get_observation",
                "compare_baseline",
                "lookup_runbook",
                "history",
            ],
        },
        # Exact operation-specific shapes are checked by application code, never dispatched blindly.
        "arguments": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "limit"],
            "properties": {
                "id": {"type": "string", "maxLength": 64},
                "limit": {"type": "integer", "minimum": 0, "maximum": 5},
            },
        },
    },
}


def validate_response(raw: str, references: set[str]) -> dict:
    data = strict_json(raw, 32768)
    require(isinstance(data, dict) and set(data) == set(RESPONSE_SCHEMA["required"]))
    require(data["kind"] in ("answer", "operation"))
    require(isinstance(data["summary"], str) and len(data["summary"]) <= 2000)
    for field in ("hypotheses", "unknowns", "checks"):
        require(isinstance(data[field], list) and len(data[field]) <= 8)
        require(all(isinstance(s, str) and len(s) <= 1000 for s in data[field]))
    refs = data["references"]
    require(isinstance(refs, list) and 1 <= len(refs) <= 24)
    require(all(isinstance(r, str) and r in references for r in refs), "unknown_evidence_id")
    args = data["arguments"]
    require(isinstance(args, dict) and set(args) == {"id", "limit"})
    require(isinstance(args["id"], str) and len(args["id"]) <= 64)
    require(integer(args["limit"], 0, 5))
    require(isinstance(data["operation"], str))
    if data["kind"] == "answer":
        require(data["operation"] == "" and args == {"id": "", "limit": 0})
    else:
        require(
            data["operation"] in RESPONSE_SCHEMA["properties"]["operation"]["enum"][1:],
            "forbidden_operation",
        )
        require(
            not data["summary"]
            and not any(
                data[k]
                for k in (
                    "hypotheses",
                    "unknowns",
                    "checks",
                )
            )
        )
    return data
