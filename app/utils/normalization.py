def normalize_str(s: str | None) -> str | None:
    # TODO: add consistent normalization (strip, lower where appropriate)
    if s is None:
        return None
    return s.strip()
