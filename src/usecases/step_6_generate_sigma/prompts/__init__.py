"""Step 6 prompts package — DLP (Detection Logic Planner) prompts."""
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


__all__ = ["load_prompt"]