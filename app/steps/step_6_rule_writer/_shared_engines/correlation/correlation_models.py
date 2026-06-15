from __future__ import annotations

from pydantic import BaseModel, Field

# Thêm model mới đại diện cho chuẩn Correlation của SigmaHQ
class SigmaCorrelationBlock(BaseModel):
    type: str  # Ví dụ: "temporal_ordered", "event_count"
    rules: list[str] = Field(default_factory=list)  # Tên các rule con
    timespan: str | None = None  # Ví dụ: "5m", "1h"
    group_by: list[str] | None = Field(alias="group-by", default=None)
    condition: dict[str, int] | None = None  # Dùng cho event_count (vd: {"gte": 5})

class CorrelationCondition(BaseModel):
    # Dùng cho single-event (cùng 1 logsource, ví dụ: cha và con)
    expression: str | None = None 
    
    # Dùng cho multi-event (khác logsource, ví dụ: ghi file -> chạy lệnh)
    is_cross_event: bool = False
    correlation_block: SigmaCorrelationBlock | None = None
    
    confidence: float
    reasoning: str
    required_selections: list[str] = Field(default_factory=list)