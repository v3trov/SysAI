from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from .config import Config, api_key


class LLMError(RuntimeError):
    """A DeepSeek transport or protocol failure."""


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        raise NotImplementedError


class DeepSeekProvider(LLMProvider):
    def __init__(self, config: Config, key: str | None = None):
        self.config = config
        self._key = key

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        payload = {"model": self.config.model, "messages": messages, "temperature": 0}
        if tools:
            payload.update({"tools": tools, "tool_choice": "auto"})
        body = json.dumps(payload).encode()
        request = urllib.request.Request(self.config.base_url.rstrip("/") + "/chat/completions", data=body,
                                         headers={"Authorization": "Bearer " + (self._key or api_key()), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read(2 * 1024 * 1024))
        except urllib.error.HTTPError as exc:
            raise LLMError(f"DeepSeek HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMError(f"DeepSeek request failed: {type(exc).__name__}") from None
        try:
            choice = data["choices"][0]
            if choice["finish_reason"] in {"length", "content_filter"}:
                raise LLMError("Incomplete API response")
            return choice["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("Malformed API response") from None


class MockLLMProvider(LLMProvider):
    def __init__(self, responses: list[dict]):
        self.responses = iter(responses)

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        return next(self.responses)
