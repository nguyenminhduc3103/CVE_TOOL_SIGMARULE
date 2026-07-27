from pydantic import BaseModel, Field
from datetime import datetime
from typing import List


class TriageContext(BaseModel):
    in_kev: bool | None = None
    kev_added_date: datetime | None = None
    ransomware_usage: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    internet_exposure: int | None = None
    public_poc: bool = False
    poc_references: List[str] | None = None
    threat_actors: List[str] | None = None
    observed_in_the_wild: bool = False
    capability_assessment: str | None = None
    priority: str | None = None
    priority_score: int | None = None
    decision: str | None = None
    decision_reason: str | None = None
    rationale: str | None = None
    telemetry_blocked: bool = False  # Step 1.4: Set True if telemetry gate blocks pipeline
    extensions: dict[str, object] | None = Field(default=None, description="Reserved for Phase 2")
