from datetime import datetime


def parse_iso8601(s: str) -> datetime | None:
    # TODO: robust ISO8601 parsing with timezone handling
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None
