"""M2b CLI transport, kept out of monitoring imports and state writes."""

import sys

from .contracts import load_settings, require
from .evidence import EvidenceReader, PackBuilder
from .service import Investigation


def dispatch(args, config, emit):
    settings = load_settings(args.ai_config)
    if args.command == "ai-benchmark":
        from .scenarios import benchmark

        result = benchmark(settings, run=args.run)
        emit(result)
        return 0 if not args.run or result["validated_answers"] == len(result["records"]) else 2
    require(args.approve is None or args.run, "approval_requires_explicit_run")
    reader = EvidenceReader(args.state)
    try:
        service = Investigation(PackBuilder(reader, config.stale_seconds), settings)
        first = True

        def approve(preview):
            nonlocal first
            if first and args.approve is not None:
                first = False
                return args.approve
            first = False
            emit({"privacy_preview": preview})
            if not sys.stdin.isatty():
                return None
            print(
                "Для отправки введите approval_token этого preview (Enter — отказ): ",
                file=sys.stderr,
                end="",
                flush=True,
            )
            return sys.stdin.readline(130).strip()

        result = service.run(args.id, approve) if args.run else service.preview(args.id)
        emit(result)
        return (
            0
            if result.get("mode") != "deterministic" or result.get("reason") == "llm_disabled"
            else 2
        )
    finally:
        reader.close()
