"""
Prompt Registry — versioned prompt management with optional Langfuse backing.

Prompts are stored as versioned entries so the active version can be
hot-swapped without restarting the service.  When LANGFUSE_PROMPT_MANAGEMENT=true
the registry first attempts to fetch the prompt from the Langfuse remote store
(using the "production" label), and falls back to the in-memory dict seeded
from templates.py on any failure — ensuring the pipeline always has a prompt.

Prompt names used in Langfuse must match the local names:
  triage_system, verdict_system, analyst_persona
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import structlog

from prompts.templates import (
    TRIAGE_SYSTEM_PROMPT,
    VERDICT_SYSTEM_PROMPT,
    ANALYST_PERSONA,
)

logger = structlog.get_logger(__name__)


@dataclass
class PromptVersion:
    name: str
    version: str
    content: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    tags: list[str] = field(default_factory=list)


class PromptRegistry:
    """In-memory versioned prompt store."""

    def __init__(self) -> None:
        self._store: dict[str, list[PromptVersion]] = {}
        self._active: dict[str, str] = {}  # name → version
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        self.register("triage_system", "v1.0", TRIAGE_SYSTEM_PROMPT, tags=["triage", "react"])
        self.register("verdict_system", "v1.0", VERDICT_SYSTEM_PROMPT, tags=["verdict"])
        self.register("analyst_persona", "v1.0", ANALYST_PERSONA, tags=["persona"])

    def register(
        self,
        name: str,
        version: str,
        content: str,
        tags: list[str] | None = None,
        set_active: bool = True,
    ) -> None:
        if name not in self._store:
            self._store[name] = []
        entry = PromptVersion(
            name=name,
            version=version,
            content=content,
            tags=tags or [],
        )
        self._store[name].append(entry)
        if set_active:
            self._active[name] = version

    def get(self, name: str, version: str | None = None) -> str:
        # Try Langfuse remote prompt store first (opt-in)
        try:
            from observability.langfuse_client import prompt_management_enabled, get_langfuse
            if prompt_management_enabled():
                lf = get_langfuse()
                if lf is not None:
                    prompt_client = lf.get_prompt(name, label="production")
                    content = prompt_client.get_langchain_prompt()
                    logger.debug("prompt_fetched_from_langfuse", name=name)
                    return content
        except Exception as exc:
            logger.debug("langfuse_prompt_fetch_failed", name=name, error=str(exc))

        # Local in-memory fallback (default behaviour)
        versions = self._store.get(name, [])
        if not versions:
            raise KeyError(f"Prompt '{name}' not found in registry")
        target = version or self._active.get(name)
        for v in versions:
            if v.version == target:
                return v.content
        # fall back to latest
        return versions[-1].content

    def set_active(self, name: str, version: str) -> None:
        if name not in self._store:
            raise KeyError(f"Prompt '{name}' not found")
        self._active[name] = version

    def list_versions(self, name: str) -> list[str]:
        return [v.version for v in self._store.get(name, [])]


# Module-level singleton
registry = PromptRegistry()
