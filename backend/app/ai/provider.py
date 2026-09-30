"""OpenAI-compatible server-side chat-completions provider adapter."""

from __future__ import annotations

import asyncio
import json
from typing import Literal, Protocol

import aiohttp

from app.ai.prompts import system_prompt, user_payload
from app.config import AiProviderSettings

AiTask = Literal["finding_explanation", "scan_summary"]
_MAX_PROVIDER_RESPONSE_BYTES = 128 * 1024


class AiProviderError(RuntimeError):
    """A provider failure without user/provider response details."""


class AiProvider(Protocol):
    name: str
    model: str

    async def generate_json(self, *, task: AiTask, data: object) -> object: ...


class OpenAICompatibleProvider:
    """Small async adapter; keys are sent only to the configured HTTPS provider."""

    def __init__(self, settings: AiProviderSettings) -> None:
        self._settings = settings
        self.name = settings.provider
        self.model = settings.model

    async def generate_json(self, *, task: AiTask, data: object) -> object:
        endpoint = f"{self._settings.base_url}/chat/completions"
        request_payload = {
            "model": self._settings.model,
            "temperature": 0.2,
            "max_tokens": 1_200,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt(task)},
                {"role": "user", "content": user_payload(data)},
            ],
        }
        timeout = aiohttp.ClientTimeout(total=self._settings.timeout_seconds, connect=5)
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.post(
                    endpoint,
                    json=request_payload,
                    headers={
                        "Authorization": f"Bearer {self._settings.api_key}",
                        "Accept": "application/json",
                    },
                    allow_redirects=False,
                ) as response:
                    if response.status < 200 or response.status >= 300:
                        raise AiProviderError("AI provider returned an unsuccessful response.")
                    body = await response.content.read(_MAX_PROVIDER_RESPONSE_BYTES + 1)
                    if len(body) > _MAX_PROVIDER_RESPONSE_BYTES:
                        raise AiProviderError("AI provider response exceeded the configured limit.")
        except AiProviderError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError) as exc:
            raise AiProviderError("AI provider request failed.") from exc
        except Exception as exc:
            raise AiProviderError("AI provider request failed.") from exc

        try:
            envelope = json.loads(body)
            content = envelope["choices"][0]["message"]["content"]
            if not isinstance(content, str) or len(content) > 16_384:
                raise ValueError("invalid content")
            return json.loads(content)
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AiProviderError("AI provider response was not valid structured JSON.") from exc
