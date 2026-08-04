"""Tests for extract_categories — stable ∪ conditional, ordered dedup."""
from __future__ import annotations

from src.usecases.step_4_telemetry import extract_categories
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeature,
    CandidateFeatures,
)


def _feature(concept: str) -> CandidateFeature:
    return CandidateFeature(semantic="x", telemetry_concept=concept, evidence=[])


def _features(stable=(), conditional=(), optional=()) -> CandidateFeatures:
    return CandidateFeatures(
        stable=[_feature(c) for c in stable],
        conditional=[_feature(c) for c in conditional],
        optional=[_feature(c) for c in optional],
    )


class TestOrdering:
    def test_stable_then_conditional(self):
        # Real KB concepts (whitelist-enforced): process_creation/file_change
        # as stable, dns_query/network_connection as conditional,
        # registry_event as optional (must be excluded).
        cf = _features(
            stable=("process_creation", "file_change"),
            conditional=("dns_query", "network_connection"),
            optional=("registry_event",),
        )
        assert extract_categories(cf) == [
            "process_creation", "file_change", "dns_query", "network_connection",
        ]

    def test_stable_first_wins_on_duplicate(self):
        cf = _features(stable=("process_creation",), conditional=("process_creation",))
        assert extract_categories(cf) == ["process_creation"]

    def test_optional_always_excluded(self):
        cf = _features(stable=(), conditional=(), optional=("dns_query", "registry_event"))
        assert extract_categories(cf) == []


class TestEmptyInputs:
    def test_all_empty(self):
        assert extract_categories(_features()) == []

    def test_stable_only(self):
        cf = _features(stable=("process_creation",))
        assert extract_categories(cf) == ["process_creation"]

    def test_conditional_only(self):
        cf = _features(conditional=("webserver",))
        assert extract_categories(cf) == ["webserver"]


class TestDeterminism:
    def test_input_order_preserved(self):
        # NOT alphabetical — input order preserved. Real KB concepts.
        cf = _features(stable=("webserver", "antivirus", "firewall"))
        assert extract_categories(cf) == ["webserver", "antivirus", "firewall"]