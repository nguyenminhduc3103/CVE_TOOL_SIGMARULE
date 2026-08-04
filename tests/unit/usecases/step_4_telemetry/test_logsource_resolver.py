"""Tests for resolve — pure mapping from categories × platforms to SigmaLogsource."""
from __future__ import annotations

from src.usecases.step_4_telemetry import (
    SigmaCategoryInfo,
    SigmaCategoryStatistics,
    SigmaLogsource,
    resolve,
)
from src.usecases.step_4_telemetry.models.telemetry_plan import TargetEnvironment


def _knowledge_fixture() -> SigmaCategoryStatistics:
    """Fixture that matches the user's exact example."""
    return SigmaCategoryStatistics.from_dict(
        {
            "process_creation": SigmaCategoryInfo(
                platforms=["windows", "linux", "macos"],
                technologies=[],
                services=[],
                fields={},
            ),
            "network_connection": SigmaCategoryInfo(
                platforms=["windows", "linux"],
                technologies=[],
                services=[],
                fields={},
            ),
            "webserver": SigmaCategoryInfo(
                platforms=[],
                technologies=[],
                services=[],
                fields={},
            ),
        }
    )


class TestExactMatchUserSpec:
    """The exact output the user requested in the original prompt."""

    def test_full_user_example(self):
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows", "linux"])
        categories = ["process_creation", "network_connection", "webserver"]

        assert resolve(knowledge, target_env, categories) == [
            SigmaLogsource(product="windows", category="process_creation"),
            SigmaLogsource(product="linux", category="process_creation"),
            SigmaLogsource(product="windows", category="network_connection"),
            SigmaLogsource(product="linux", category="network_connection"),
            SigmaLogsource(product=None, category="webserver"),
        ]


class TestEdgeCases:
    def test_empty_categories(self):
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows", "linux"])
        assert resolve(knowledge, target_env, []) == []

    def test_empty_platforms(self):
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=[])
        categories = ["process_creation", "webserver"]
        # process_creation has products but no platform to match → empty.
        # webserver is global → emits one entry.
        assert resolve(knowledge, target_env, categories) == [
            SigmaLogsource(product=None, category="webserver"),
        ]

    def test_no_platform_match(self):
        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "process_creation": SigmaCategoryInfo(
                    platforms=["windows", "linux"],
                    technologies=[],
                    services=[],
                    fields={},
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["aix"])
        assert resolve(knowledge, target_env, ["process_creation"]) == []

    def test_global_only(self):
        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "webserver": SigmaCategoryInfo(
                    platforms=[], technologies=[], services=[], fields={}
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["windows", "linux"])
        assert resolve(knowledge, target_env, ["webserver"]) == [
            SigmaLogsource(product=None, category="webserver")
        ]

    def test_unknown_category_is_global(self):
        """Categories not in the stats file are treated as global."""
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows"])
        assert resolve(knowledge, target_env, ["does_not_exist"]) == [
            SigmaLogsource(product=None, category="does_not_exist")
        ]

    def test_dedup_by_product_category(self):
        """Same (product, category) emitted only once even if category repeats."""
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows"])
        # Repeat `process_creation` to ensure dedup.
        categories = ["process_creation", "process_creation"]
        assert resolve(knowledge, target_env, categories) == [
            SigmaLogsource(product="windows", category="process_creation"),
        ]

    def test_dedup_global_to_global(self):
        """Repeated global category → single entry."""
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows"])
        categories = ["webserver", "webserver"]
        assert resolve(knowledge, target_env, categories) == [
            SigmaLogsource(product=None, category="webserver")
        ]


class TestOrderingIsPreserved:
    def test_category_and_platform_order(self):
        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "process_creation": SigmaCategoryInfo(
                    platforms=["windows", "linux", "macos"],
                    technologies=[],
                    services=[],
                    fields={},
                ),
            }
        )
        # Reverse input order — output must follow input order.
        target_env = TargetEnvironment(platforms=["macos", "linux", "windows"])
        assert resolve(knowledge, target_env, ["process_creation"]) == [
            SigmaLogsource(product="macos", category="process_creation"),
            SigmaLogsource(product="linux", category="process_creation"),
            SigmaLogsource(product="windows", category="process_creation"),
        ]


class TestAllowedFieldsUserSpec:
    """User's extended spec: each SigmaLogsource carries allowed_fields."""

    def test_process_creation_windows_has_allowed_fields(self):
        from src.usecases.step_4_telemetry import SigmaFieldStats

        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "process_creation": SigmaCategoryInfo(
                    platforms=["windows", "linux", "macos"],
                    technologies=[],
                    services=[],
                    fields={
                        "Image": SigmaFieldStats(
                            count=5,
                            operators=["contains", "endswith", "exact", "startswith"],
                        ),
                        "ParentImage": SigmaFieldStats(
                            count=2, operators=["contains", "endswith"]
                        ),
                        "CommandLine": SigmaFieldStats(
                            count=3, operators=["contains", "re"]
                        ),
                    },
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["process_creation"])
        win = result[0]
        assert win.product == "windows"
        assert win.category == "process_creation"
        assert win.allowed_fields == {
            "Image": ["contains", "endswith", "exact", "startswith"],
            "ParentImage": ["contains", "endswith"],
            "CommandLine": ["contains", "re"],
        }

    def test_global_category_still_carries_fields(self):
        from src.usecases.step_4_telemetry import SigmaFieldStats

        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "webserver": SigmaCategoryInfo(
                    platforms=[],
                    technologies=[],
                    services=[],
                    fields={
                        "cs-method": SigmaFieldStats(count=3, operators=["exact"]),
                        "cs-uri-query": SigmaFieldStats(
                            count=2, operators=["contains"]
                        ),
                    },
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["webserver"])
        assert result[0].product is None
        assert result[0].allowed_fields == {
            "cs-method": ["exact"],
            "cs-uri-query": ["contains"],
        }

    def test_unknown_category_has_empty_fields(self):
        knowledge = _knowledge_fixture()
        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["does_not_exist"])
        assert result == [
            SigmaLogsource(
                product=None, category="does_not_exist", allowed_fields={}
            )
        ]

    def test_empty_fields_propagate(self):
        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "network_connection": SigmaCategoryInfo(
                    platforms=["windows"],
                    technologies=[],
                    services=[],
                    fields={},
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["network_connection"])
        assert result[0].allowed_fields == {}

    def test_operators_order_preserved(self):
        """Operators follow source order — no sorting."""
        from src.usecases.step_4_telemetry import SigmaFieldStats

        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "process_creation": SigmaCategoryInfo(
                    platforms=["windows"],
                    technologies=[],
                    services=[],
                    fields={
                        "Image": SigmaFieldStats(
                            count=1, operators=["z", "a", "m", "b"]
                        ),
                    },
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["process_creation"])
        assert result[0].allowed_fields == {"Image": ["z", "a", "m", "b"]}

    def test_empty_string_field_name_filtered(self):
        """Source JSON sometimes has "" field name (e.g. application) — filtered."""
        from src.usecases.step_4_telemetry import SigmaFieldStats

        knowledge = SigmaCategoryStatistics.from_dict(
            {
                "application": SigmaCategoryInfo(
                    platforms=[],
                    technologies=["jvm"],
                    services=[],
                    fields={
                        "": SigmaFieldStats(count=1, operators=["all"]),
                        "logtype": SigmaFieldStats(count=2, operators=["exact"]),
                    },
                ),
            }
        )
        target_env = TargetEnvironment(platforms=["linux"])
        result = resolve(knowledge, target_env, ["application"])
        assert "" not in result[0].allowed_fields
        assert result[0].allowed_fields == {"logtype": ["exact"]}


class TestAllowedFieldsRealFile:
    """End-to-end: real sigma_category_statistics.json is wired correctly."""

    def test_real_process_creation_image_field(self):
        from src.usecases.step_4_telemetry import (
            invalidate_statistics_cache,
            load_statistics,
        )

        invalidate_statistics_cache()
        knowledge = load_statistics()
        info = knowledge.get("process_creation")
        assert info is not None
        # We don't pin the exact list — SigmaHQ may update over time.
        image_ops = info.fields["Image"].operators
        assert isinstance(image_ops, list)
        assert "endswith" in image_ops or "exact" in image_ops

        target_env = TargetEnvironment(platforms=["windows"])
        result = resolve(knowledge, target_env, ["process_creation"])
        assert result[0].allowed_fields["Image"] == image_ops