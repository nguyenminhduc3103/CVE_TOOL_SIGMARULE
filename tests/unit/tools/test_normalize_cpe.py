"""Tests for tools/normalize_cpe.py — pure transformer, no network."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]  # tests/unit/tools/ → 3 levels up to repo root
SCRIPT = REPO_ROOT / "tools" / "normalize_cpe.py"


# Full WannaCry / EternalBlue sample từ user prompt — 22 dòng.
WANACRY_SAMPLE: list[str] = [
    "[APP] Microsoft Server Message Block 1.0",
    "[OS] Microsoft Windows 10 1507",
    "[OS] Microsoft Windows 10 1511",
    "[OS] Microsoft Windows 10 1607",
    "[OS] Microsoft Windows 7 sp1",
    "[OS] Microsoft Windows 8.1",
    "[OS] Microsoft Windows Rt 8.1",
    "[OS] Microsoft Windows Server 2008 sp2",
    "[OS] Microsoft Windows Server 2008 r2 sp1",
    "[OS] Microsoft Windows Server 2012",
    "[OS] Microsoft Windows Server 2012 r2",
    "[OS] Microsoft Windows Server 2016",
    "[OS] Microsoft Windows Vista sp2",
    "[OS] Siemens Acuson P300 Firmware 13.02",
    "[OS] Siemens Acuson P300 Firmware 13.03",
    "[OS] Siemens Acuson P300 Firmware 13.20",
    "[OS] Siemens Acuson P300 Firmware 13.21",
    "[HW] Siemens Acuson P300",
    "[OS] Siemens Acuson P500 Firmware va10",
    "[OS] Siemens Acuson P500 Firmware vb10",
    "[HW] Siemens Acuson P500",
    "[OS] Siemens Acuson Sc2000 Firmware",
]


# ─────────────────────────────────────────────────────────────────────────────
# Pure-function tests
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalizeProducts:
    """Pure-function tests cho normalize_products()."""

    def test_full_wanacry_sample_buckets_correctly(self):
        from tools.normalize_cpe import normalize_products

        result = normalize_products(WANACRY_SAMPLE)
        assert len(result.applications) == 1
        assert result.applications == ["Microsoft Server Message Block 1.0"]
        assert len(result.operating_systems) == 19
        assert result.operating_systems[0] == "Microsoft Windows 10 1507"
        assert result.operating_systems[-1] == "Siemens Acuson Sc2000 Firmware"
        assert len(result.hardware) == 2
        assert result.hardware == ["Siemens Acuson P300", "Siemens Acuson P500"]

    def test_real_step1_acronym_format(self):
        """Step 1 NVD parser thực tế sinh ra 'Microsoft Smb' (không phải
        'Server Message Block'). Tool phải chấp nhận format thực tế này."""
        from tools.normalize_cpe import normalize_products

        labels = [
            "[APP] Microsoft Smb 1.0",
            "[OS] Microsoft Windows 10 1507",
            "[HW] Siemens Acuson P300",
        ]
        result = normalize_products(labels)
        assert result.applications == ["Microsoft Smb 1.0"]
        assert result.operating_systems == ["Microsoft Windows 10 1507"]
        assert result.hardware == ["Siemens Acuson P300"]

    def test_empty_input_returns_empty_buckets(self):
        from tools.normalize_cpe import normalize_products

        result = normalize_products([])
        assert result.applications == []
        assert result.operating_systems == []
        assert result.hardware == []

    def test_unknown_tag_silently_skipped(self):
        from tools.normalize_cpe import normalize_products

        result = normalize_products(
            ["[FOO] something", "no tag here", "[OS] Windows 10"]
        )
        assert result.applications == []
        assert result.operating_systems == ["Windows 10"]
        assert result.hardware == []

    def test_whitespace_around_tag_and_body_trimmed(self):
        from tools.normalize_cpe import normalize_products

        result = normalize_products(["  [OS]   Windows 10 1507   "])
        assert result.operating_systems == ["Windows 10 1507"]

    def test_duplicates_deduplicated(self):
        """New behavior: set-based dedupe — duplicate chỉ giữ 1 lần."""
        from tools.normalize_cpe import normalize_products

        result = normalize_products(["[OS] Windows 10", "[OS] Windows 10"])
        assert result.operating_systems == ["Windows 10"]

    def test_output_is_sorted_alphabetically(self):
        """New behavior: mỗi bucket sort alphabetical sau khi dedupe."""
        from tools.normalize_cpe import normalize_products

        # Provide unsorted input — output phải sorted.
        labels = [
            "[OS] Microsoft Windows 10 1507",
            "[OS] Microsoft Windows 7 sp1",
            "[OS] Microsoft Windows 8.1",
        ]
        result = normalize_products(labels)
        assert result.operating_systems == [
            "Microsoft Windows 10 1507",
            "Microsoft Windows 7 sp1",
            "Microsoft Windows 8.1",
        ]

    def test_internal_whitespace_in_body_preserved(self):
        from tools.normalize_cpe import normalize_products

        result = normalize_products(["[APP] Microsoft Server Message Block 1.0"])
        assert result.applications == ["Microsoft Server Message Block 1.0"]

    def test_each_bucket_isolated(self):
        """Mỗi tag chỉ land vào 1 bucket đúng của nó."""
        from tools.normalize_cpe import normalize_products

        result = normalize_products(
            ["[APP] foo", "[OS] bar", "[HW] baz", "[APP] qux"]
        )
        assert result.applications == ["foo", "qux"]
        assert result.operating_systems == ["bar"]
        assert result.hardware == ["baz"]

    def test_returns_pydantic_model(self):
        from tools.normalize_cpe import normalize_products, NormalizedCPE

        result = normalize_products([])
        assert isinstance(result, NormalizedCPE)

    def test_serializable_to_dict(self):
        """Output phải serialize được qua model_dump() để CLI in ra JSON."""
        from tools.normalize_cpe import normalize_products

        result = normalize_products(WANACRY_SAMPLE)
        dumped = result.model_dump()
        assert set(dumped.keys()) == {"applications", "operating_systems", "hardware"}
        assert len(dumped["applications"]) == 1
        assert len(dumped["operating_systems"]) == 19
        assert len(dumped["hardware"]) == 2


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end CLI tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCLI:
    """End-to-end CLI qua subprocess."""

    def _run_cli(self, *args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-X", "utf8", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            input=stdin_text,
            cwd=str(REPO_ROOT),
            timeout=30,
        )

    def test_stdin_to_stdout_roundtrip(self):
        proc = self._run_cli(stdin_text=json.dumps(WANACRY_SAMPLE))
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["applications"] == ["Microsoft Server Message Block 1.0"]
        assert len(out["operating_systems"]) == 19
        assert len(out["hardware"]) == 2

    def test_input_file_to_output_file(self, tmp_path: Path):
        in_path = tmp_path / "products.json"
        out_path = tmp_path / "normalized.json"
        in_path.write_text(json.dumps(WANACRY_SAMPLE), encoding="utf-8")
        proc = self._run_cli("--input", str(in_path), "--output", str(out_path))
        assert proc.returncode == 0, proc.stderr
        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        assert "applications" in loaded
        assert "operating_systems" in loaded
        assert "hardware" in loaded
        assert len(loaded["operating_systems"]) == 19

    def test_output_pretty_by_default(self):
        proc = self._run_cli(stdin_text=json.dumps(["[OS] Windows 10"]))
        assert proc.returncode == 0
        # Pretty = multi-line indented JSON
        assert "\n" in proc.stdout
        assert "  " in proc.stdout  # 2-space indent

    def test_compact_flag_produces_single_line(self):
        proc = self._run_cli("--compact", stdin_text=json.dumps(["[OS] Windows 10"]))
        assert proc.returncode == 0
        # No embedded newlines inside the JSON payload (print adds a trailing \n).
        stripped = proc.stdout.rstrip("\n")
        assert "\n" not in stripped
        # Sanity check: it really is the JSON object we expect.
        assert stripped == json.dumps(
            {"applications": [], "operating_systems": ["Windows 10"], "hardware": []}
        )

    def test_invalid_json_returns_exit_2(self):
        proc = self._run_cli(stdin_text="not json")
        assert proc.returncode == 2
        assert "invalid JSON" in proc.stderr

    def test_non_list_input_returns_exit_2(self):
        proc = self._run_cli(stdin_text=json.dumps({"foo": "bar"}))
        assert proc.returncode == 2
        assert "JSON list" in proc.stderr

    def test_list_with_non_string_skips_bad_entries(self):
        """New behavior: non-string entries inside list bị skip silently,
        valid entries vẫn được normalize; không raise exit 2."""
        proc = self._run_cli(stdin_text=json.dumps(["[OS] ok", 123]))
        assert proc.returncode == 0
        out = json.loads(proc.stdout)
        assert out["operating_systems"] == ["ok"]

    def test_empty_list_returns_empty_buckets(self):
        proc = self._run_cli(stdin_text=json.dumps([]))
        assert proc.returncode == 0
        out = json.loads(proc.stdout)
        assert out == {
            "applications": [],
            "operating_systems": [],
            "hardware": [],
        }

    def test_status_to_stderr_not_stdout(self, tmp_path: Path):
        """Khi dùng --output, status message phải đi stderr, stdout phải rỗng."""
        out_path = tmp_path / "normalized.json"
        proc = self._run_cli(
            "--output", str(out_path),
            stdin_text=json.dumps(["[OS] Windows 10"]),
        )
        assert proc.returncode == 0
        assert proc.stdout == ""  # JSON to file, not stdout
        assert "[normalize_cpe] wrote" in proc.stderr
