from pydantic import BaseModel, Field
from datetime import datetime
from typing import List


class CoreCVEData(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    cwe_ids: List[str] | None = None
    references: List[str] | None = None
    cpes: List[str] | None = None
    affected_products: List[str] | None = Field(default=None, description="Reserved for Phase 2")
    published_at: datetime | None = None
    modified_at: datetime | None = None
