from __future__ import annotations

from pydantic import BaseModel, Field


class SigmaMetadata(BaseModel):
    title: str
    id: str
    status: str
    description: str
    references: list[str] = Field(default_factory=list)
    author: str | None = None
    date: str | None = None
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    level: str = "medium"
    related: list[dict[str, str]] = Field(default_factory=list)