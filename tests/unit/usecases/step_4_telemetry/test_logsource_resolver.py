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