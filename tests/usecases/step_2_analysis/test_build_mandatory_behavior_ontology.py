"""Unit tests for scripts/build_mandatory_behavior_ontology.py CLI."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Resolve repo root once; tests use absolute paths to avoid cwd dependency.
REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "build_mandatory_behavior_ontology.py"
SOURCE_DEFAULT = REPO_ROOT / ".cache" / "ontology" / "primitive_behavior_ontology.json"
OUTPUT_DEFAULT = REPO_ROOT / ".cache" / "ontology" / "mandatory_behavior_ontology.json"


class TestBuildFunction:
    """Tests for `build_mandatory_behavior_ontology.build` (pure function)."""

    def _write_input(self, tmp_path: Path, primitives: list[dict]) -> Path:
        src = tmp_path / "in.json"
        src.write_text(
            json.dumps({"primitives": primitives, "count": len(primitives)}),
            encoding="utf-8",
        )
        return src

    def test_drops_aliases_and_capecs(self, tmp_path: Path) -> None:
        # Import lazily so a missing optional dep elsewhere doesn't fail collection.
        from scripts.build_mandatory_behavior_ontology import build

        src = self._write_input(tmp_path, [
            {
                "primitive": "sql_injection",
                "aliases": ["sqli", "sql_cmd"],
                "description": "Inject SQL via user input.",
                "capecs": ["CAPEC-66"],
            }
        ])
        out = tmp_path / "out.json"
        rc = build(src, out)
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        entry = data["entries"][0]
        assert "aliases" not in entry
        assert "capecs" not in entry
        assert entry == {"primitive": "sql_injection", "description": "Inject SQL via user input."}

    def test_count_matches_input(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        primitives = [
            {"primitive": f"tok_{i}", "description": f"desc {i}",
             "aliases": [f"alias_{i}"], "capecs": ["CAPEC-1"]}
            for i in range(5)
        ]
        src = self._write_input(tmp_path, primitives)
        out = tmp_path / "out.json"
        rc = build(src, out)
        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8"))["count"] == 5

    def test_skips_empty_primitive(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        src = self._write_input(tmp_path, [
            {"primitive": "valid_one", "description": "ok"},
            {"primitive": "", "description": "empty token skipped"},
            {"primitive": "   ", "description": "whitespace token skipped"},
        ])
        out = tmp_path / "out.json"
        rc = build(src, out)
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["count"] == 1
        assert data["entries"][0]["primitive"] == "valid_one"
        assert data["skipped_empty_primitive"] == 2

    def test_empty_input_returns_error(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        src = self._write_input(tmp_path, [])
        out = tmp_path / "out.json"
        rc = build(src, out)
        assert rc == 1
        assert not out.exists()

    def test_missing_source_returns_error(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        rc = build(tmp_path / "nope.json", tmp_path / "out.json")
        assert rc == 1

    def test_invalid_json_returns_error(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        src = tmp_path / "bad.json"
        src.write_text("{not valid json", encoding="utf-8")
        rc = build(src, tmp_path / "out.json")
        assert rc == 1

    def test_overwrites_existing_output(self, tmp_path: Path) -> None:
        from scripts.build_mandatory_behavior_ontology import build

        src = self._write_input(tmp_path, [
            {"primitive": "tok_a", "description": "desc a"},
        ])
        out = tmp_path / "out.json"
        build(src, out)
        first = out.read_text(encoding="utf-8")

        # Rebuild with different input - should overwrite, not append.
        src2 = self._write_input(tmp_path, [
            {"primitive": "tok_b", "description": "desc b"},
            {"primitive": "tok_c", "description": "desc c"},
        ])
        rc = build(src2, out)
        assert rc == 0
        second = json.loads(out.read_text(encoding="utf-8"))
        assert second["count"] == 2
        assert "tok_a" not in out.read_text(encoding="utf-8")
        assert "tok_a" not in first or first != out.read_text(encoding="utf-8")


@pytest.mark.skipif(
    not SOURCE_DEFAULT.exists(),
    reason="Primitive ontology not built yet; skip end-to-end test.",
)
class TestEndToEnd:
    """Run the CLI as a subprocess and verify real output."""

    def test_cli_builds_default_paths(self) -> None:
        if OUTPUT_DEFAULT.exists():
            OUTPUT_DEFAULT.unlink()  # ensure CLI actually writes
        result = subprocess.run(
            [sys.executable, "-X", "utf8", str(SCRIPT)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, result.stderr
        assert OUTPUT_DEFAULT.exists()
        data = json.loads(OUTPUT_DEFAULT.read_text(encoding="utf-8"))
        assert data["count"] == 110
        assert data["count"] == len(data["entries"])
        # Every entry has exactly the two required keys.
        for entry in data["entries"]:
            assert set(entry.keys()) == {"primitive", "description"}
            assert entry["primitive"]
            assert isinstance(entry["description"], str)
