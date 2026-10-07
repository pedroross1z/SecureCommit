"""Wrapper da API Anthropic com schema, retry, cache e telemetria."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from pathlib import Path
from typing import Type, TypeVar

from anthropic import Anthropic, APIError, APIStatusError
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AICache

logger = logging.getLogger("aspm.ai")

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_VERSION_RE = re.compile(r"<!--\s*version:\s*(\S+)\s*-->")
_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# Semaforo global limita concorrencia total (spec: no maximo 5).
_ai_semaphore = threading.Semaphore(settings.ai_max_concurrency)

T = TypeVar("T", bound=BaseModel)


class AIUnavailableError(RuntimeError):
    """Falha na chamada de IA depois de retry — chamador degrada gracioso."""


def load_prompt(name: str) -> tuple[str, str]:
    """Carrega prompt de app/ai/prompts/{name}.md e extrai `version`."""
    path = _PROMPTS_DIR / f"{name}.md"
    text = path.read_text(encoding="utf-8")
    m = _VERSION_RE.search(text)
    version = m.group(1) if m else "v0"
    return text, version


_VAR_RE = re.compile(r"<<([A-Z0-9_]+)>>")


def _render_prompt(template: str, vars: dict) -> str:
    """Substitui <<NAME>> por vars['name']. Nao colide com JSON."""
    def _sub(m: re.Match) -> str:
        key = m.group(1).lower()
        val = vars.get(key)
        if val is None:
            return m.group(0)
        return str(val)
    return _VAR_RE.sub(_sub, template)


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = _JSON_FENCE_RE.sub("", s).strip()
    return s


def _make_cache_key(prompt_version: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{prompt_version}|{fingerprint}".encode()).hexdigest()


class AIClient:
    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or settings.anthropic_api_key
        self._enabled = bool(key)
        self._client = Anthropic(api_key=key) if self._enabled else None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def call_structured(
        self,
        *,
        prompt_name: str,
        prompt_vars: dict,
        response_model: Type[T],
        model: str,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        system: str | None = None,
        cache_fingerprint: str | None = None,
        db: Session | None = None,
    ) -> tuple[T, dict]:
        """Chama a API, valida JSON, retry uma vez em erro de schema.

        Retorna (parsed_model, telemetry). Telemetry inclui model, prompt_version,
        input_tokens, output_tokens, cached (bool).
        """
        if not self._enabled:
            raise AIUnavailableError("ANTHROPIC_API_KEY nao configurada")

        prompt_template, prompt_version = load_prompt(prompt_name)
        prompt = _render_prompt(prompt_template, prompt_vars)

        cache_key = None
        if cache_fingerprint and db is not None:
            cache_key = _make_cache_key(prompt_version, cache_fingerprint)
            cached = db.get(AICache, cache_key)
            if cached is not None:
                try:
                    parsed = response_model.model_validate(cached.response)
                    return parsed, {
                        "model": model,
                        "prompt_version": prompt_version,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cached": True,
                    }
                except ValidationError:
                    logger.warning("cache invalido para %s, refazendo", cache_key)

        with _ai_semaphore:
            parsed, tokens = self._call_with_retry(
                model=model,
                system=system,
                prompt=prompt,
                response_model=response_model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        if cache_key and db is not None:
            try:
                db.merge(AICache(cache_key=cache_key, response=parsed.model_dump(mode="json")))
                db.commit()
            except Exception:
                db.rollback()
                logger.exception("falha ao gravar ai_cache")

        return parsed, {
            "model": model,
            "prompt_version": prompt_version,
            "input_tokens": tokens[0],
            "output_tokens": tokens[1],
            "cached": False,
        }

    def _call_with_retry(
        self,
        *,
        model: str,
        system: str | None,
        prompt: str,
        response_model: Type[T],
        max_tokens: int,
        temperature: float,
    ) -> tuple[T, tuple[int, int]]:
        last_error: Exception | None = None
        current_prompt = prompt
        for attempt in range(2):
            try:
                kwargs: dict = {
                    "model": model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": [{"role": "user", "content": current_prompt}],
                }
                if system:
                    kwargs["system"] = system
                resp = self._client.messages.create(**kwargs)
                raw = resp.content[0].text if resp.content else ""
                cleaned = _strip_fences(raw)
                try:
                    data = json.loads(cleaned)
                except json.JSONDecodeError as je:
                    raise ValidationError.from_exception_data(
                        response_model.__name__,
                        [{"type": "json_invalid", "loc": ("__root__",), "msg": str(je), "input": cleaned}],
                    )
                parsed = response_model.model_validate(data)
                return parsed, (resp.usage.input_tokens, resp.usage.output_tokens)
            except (ValidationError, json.JSONDecodeError) as e:
                last_error = e
                logger.warning("schema invalido (tentativa %d): %s", attempt + 1, e)
                current_prompt = (
                    f"{prompt}\n\n"
                    f"Sua resposta anterior nao passou na validacao. Erro:\n{e}\n"
                    f"Responda novamente APENAS com JSON valido segundo o schema."
                )
            except APIStatusError as e:
                logger.error("Anthropic API status error: %s", e)
                raise AIUnavailableError(f"api_status={e.status_code}") from e
            except APIError as e:
                logger.error("Anthropic API error: %s", e)
                raise AIUnavailableError(str(e)) from e

        raise AIUnavailableError(f"schema invalido apos retry: {last_error}")


_client_instance: AIClient | None = None


def get_ai() -> AIClient:
    global _client_instance
    if _client_instance is None:
        _client_instance = AIClient()
    return _client_instance
