# SigmaLogsource — minimal, frozen. Resolver is service-insensitive.
#
# A SigmaLogsource identifies a Sigma rule by `category` (required) and
# optionally `product`. `product` is None when the category is not tied to
# any specific product (e.g. webserver, proxy, application at the KB
# whitelist level).
#
# No `service` field: the resolver collapses multiple services into one
# logsource per (product, category) pair. This matches the user's spec
# ("không quan tâm service").
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SigmaLogsource(BaseModel):
    """Minimal Sigma logsource identity. Frozen for hashability + dedup safety."""

    model_config = ConfigDict(frozen=True)

    category: str
    product: str | None = None