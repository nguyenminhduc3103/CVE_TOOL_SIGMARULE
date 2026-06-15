"""Base AI client (OpenAI-compatible: Groq, Anthropic, Ollama)."""
from __future__ import annotations

import asyncio
import logging

from openai import AsyncOpenAI

from app.core.config import settings

logger = logging.getLogger(__name__)


class AIServiceError(Exception):
    """Raised when AI call cannot be fulfilled."""
    pass


class BaseAIClient:
    """Thin async wrapper around OpenAI AsyncClient. Subclasses (behavior, telemetry, etc.)
    add domain-specific prompt assembly on top of call_llm."""

    def __init__(self) -> None:
        self.api_key = getattr(settings, 'ai_api_key', None)
        self.base_url = getattr(settings, 'ai_base_url', None)
        self.ai_enabled = getattr(settings, 'ai_enabled', False)

        if self.ai_enabled:
            self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
        else:
            self.client = None
            logger.info('AI disabled by configuration (ai_enabled=False).')

    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = 'llama3-70b-8192',
        max_retries: int = 3,
    ) -> str:
        if not self.ai_enabled or not self.client:
            raise AIServiceError('AI is disabled.')

        for attempt in range(max_retries):
            try:
                response = await self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {'role': 'system', 'content': system_prompt},
                        {'role': 'user', 'content': user_prompt},
                    ],
                    max_tokens=4096,
                    temperature=0.0,
                )
                return response.choices[0].message.content
            except Exception as e:
                if attempt == max_retries - 1:
                    raise AIServiceError(
                        f'AI Call failed after {max_retries} attempts: {e}'
                    )
                logger.warning(f'AI call attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in 2s.')
                await asyncio.sleep(2)
