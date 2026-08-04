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

from pydantic import BaseModel, ConfigDict, Field


class SigmaLogsource(BaseModel):
    """Sigma logsource identity + the SigmaHQ fields a rule can match.

    `allowed_fields` is populated by the resolver at post-pass time from
    `SigmaCategoryInfo.fields`. Field name → list of SigmaHQ operators
    seen in the corpus for the matched category. Key order and operator
    order follow the source JSON (deterministic, no sorting).

    No `service` field: resolver is service-insensitive (services per
    category are kept in `SigmaCategoryInfo.services` for downstream).
    """

    model_config = ConfigDict(frozen=True)

    category: str
    product: str | None = None
    allowed_fields: dict[str, list[str]] = Field(default_factory=dict)