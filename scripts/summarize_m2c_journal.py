"""Minimize an operator's bounded journal JSON sample. Never invokes host commands."""

import json
import sys

from security_orchestrator.adapters.journal import parse_row
from security_orchestrator.investigation.contracts import require, strict_json


def summarize(raw: bytes) -> dict:
    require(len(raw) <= 2 * 1024 * 1024)
    require(not raw or raw.endswith(b"\n"))
    lines = [line for line in raw.splitlines() if line.strip()]
    require(len(lines) <= 256)
    counts = {"service": 0, "timer": 0}
    for line in lines:
        _, event = parse_row(strict_json(line, 16384))
        if event:
            counts["service" if event.unit.endswith(".service") else "timer"] += 1
    return {
        "sample_records": len(lines),
        "accepted_service_events": counts["service"],
        "accepted_timer_events": counts["timer"],
        "target_events_observed": bool(sum(counts.values())),
        "complete_history": False,
    }


def main():
    try:
        result = summarize(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        print('{"sample":"invalid_or_unavailable"}')
        return 2
    print(json.dumps(result))
    return 0 if result["target_events_observed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
