"""Fixed endpoints, bounded transport, no redirects, retries, tools or remote error text."""

from dataclasses import dataclass
from decimal import Decimal
import http.client
import multiprocessing
import os
import ssl
import time
from typing import Protocol

from ..model import encode
from .contracts import MAX_WIRE, RESPONSE_SCHEMA, Settings, integer, require, strict_json


@dataclass(frozen=True)
class Reply:
    text: str
    input_tokens: int
    output_tokens: int
    cost_microusd: int
    metrics: dict


class Provider(Protocol):
    def complete(self, body: dict, settings: Settings, timeout: float) -> Reply: ...


def request_body(messages: list[dict], settings: Settings) -> dict:
    if settings.provider == "openrouter":
        return {
            "model": settings.model,
            "messages": messages,
            "stream": False,
            "max_tokens": settings.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "investigation_v1",
                    "strict": True,
                    "schema": RESPONSE_SCHEMA,
                },
            },
            "provider": {
                "only": list(settings.allowed_providers),
                "allow_fallbacks": False,
                "require_parameters": True,
                "data_collection": "deny",
                "zdr": True,
                "max_price": {
                    "prompt": settings.input_price_microusd_per_million / 1_000_000,
                    "completion": settings.output_price_microusd_per_million / 1_000_000,
                    "request": 0,
                    "image": 0,
                },
            },
        }
    return {
        "model": settings.model,
        "messages": messages,
        "stream": False,
        "format": RESPONSE_SCHEMA,
        "keep_alive": 0,
        "think": False,
        "options": {
            "num_predict": settings.max_output_tokens,
            "num_ctx": settings.max_input_tokens + settings.max_output_tokens,
            "temperature": 0,
        },
    }


def _http_exchange(body, provider, credential, timeout):
    """Called only inside a disposable transport process; stdout/stderr carry no content."""
    cloud = provider == "openrouter"
    connection = (
        http.client.HTTPSConnection(
            "openrouter.ai", timeout=timeout, context=ssl.create_default_context()
        )
        if cloud
        else http.client.HTTPConnection("127.0.0.1", 11434, timeout=timeout)
    )
    try:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if cloud:
            headers["Authorization"] = "Bearer " + credential
        connection.request(
            "POST",
            "/api/v1/chat/completions" if cloud else "/api/chat",
            body=encode(body).encode("ascii"),
            headers=headers,
        )
        response = connection.getresponse()
        require(response.status == 200, "provider_http_failure")
        require(response.getheader("Content-Encoding", "identity") == "identity")
        require(response.getheader("Content-Type", "").split(";", 1)[0] == "application/json")
        if response.getheader("Content-Length") is not None:
            require(0 <= int(response.getheader("Content-Length")) <= MAX_WIRE)
        raw = response.read(MAX_WIRE + 1)
        require(len(raw) <= MAX_WIRE, "provider_response_limit")
        return raw
    finally:
        connection.close()


def _worker(sender, body, provider, credential, timeout):
    try:
        sender.send_bytes(_http_exchange(body, provider, credential, timeout))
    except Exception:
        sender.send_bytes(b"{}")
    finally:
        sender.close()


def bounded_exchange(body, provider, credential, timeout):
    require(len(encode(body)) <= MAX_WIRE, "provider_request_limit")
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker, args=(sender, body, provider, credential, timeout), daemon=True
    )
    try:
        started = time.monotonic()
        process.start()
        sender.close()
        require(receiver.poll(max(0, timeout - (time.monotonic() - started))), "provider_timeout")
        return receiver.recv_bytes(MAX_WIRE)
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            process.close()


class HTTPProvider:
    def complete(self, body, settings, timeout):
        credential = ""
        if settings.provider == "openrouter":
            credential = os.environ.get("OPENROUTER_API_KEY", "")
            require(
                0 < len(credential) <= 512
                and credential.isascii()
                and not any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in credential),
                "cloud_credential_unavailable",
            )
        data = strict_json(bounded_exchange(body, settings.provider, credential, timeout))
        require(isinstance(data, dict) and "error" not in data, "provider_failure")
        metrics = {}
        if settings.provider == "openrouter":
            require(data.get("model") == settings.model, "provider_model_mismatch")
            route = data.get("provider")
            if route is None:
                endpoints = (
                    data.get("openrouter_metadata", {}).get("endpoints", {}).get("available", [])
                )
                require(isinstance(endpoints, list) and len(endpoints) <= 64)
                selected = [
                    e for e in endpoints if isinstance(e, dict) and e.get("selected") is True
                ]
                require(len(selected) == 1, "provider_route_unconfirmed")
                route = selected[0].get("provider")
            require(route in settings.allowed_providers, "provider_route_mismatch")
            choices = data.get("choices")
            require(isinstance(choices, list) and len(choices) == 1)
            choice = choices[0]
            require(choice.get("finish_reason") == "stop", "provider_incomplete")
            message, usage = choice["message"], data["usage"]
            input_tokens, output_tokens = usage["prompt_tokens"], usage["completion_tokens"]
            require(type(usage.get("cost")) in (int, float), "missing_provider_cost")
            cost = Decimal(str(usage["cost"])) * 1_000_000
            require(cost.is_finite() and 0 <= cost <= 100_000_000)
            cost_microusd = int(cost.to_integral_value(rounding="ROUND_CEILING"))
        else:
            require(data.get("model") == settings.model, "provider_model_mismatch")
            require(
                data.get("done") is True and data.get("done_reason") == "stop",
                "provider_incomplete",
            )
            message = data["message"]
            input_tokens, output_tokens = data["prompt_eval_count"], data["eval_count"]
            cost_microusd = 0
            for key in ("total_duration", "load_duration", "prompt_eval_duration", "eval_duration"):
                require(integer(data.get(key), 0, 10**15))
                metrics[key] = data[key]
        require(
            isinstance(message, dict)
            and not message.get("tool_calls")
            and message.get("role") == "assistant",
            "unexpected_provider_tools",
        )
        require(isinstance(message.get("content"), str) and len(message["content"]) <= 32768)
        require(integer(input_tokens) and integer(output_tokens))
        return Reply(message["content"], input_tokens, output_tokens, cost_microusd, metrics)
