"""Step6Validator — business-rule checks (architect v9).

Consolidated test file covering all seven validator invariants:
  1. Detection ID format (`^rule_[1-9][0-9]*$`)
  2. Detection ID uniqueness
  3. Per-logsource uniqueness (one detection per (category, product))
  4. Search-space respect — invented category/product/field/modifier rejected
  5. Modifier-None rule: empty `allowed_fields[field]` ⇒ no modifier;
     non-empty ⇒ modifier required
  6. Correlation rules resolve (refs ∈ detections[].id)
  7. Correlation requires ≥ 2 detections

Plus a sanity check that the validator is INDEPENDENT of Pydantic — i.e.
`Step6Result.model_validate(...)` passes for structurally valid but
semantically violating output, and only the validator raises.

NOTE: Bad IDs/refs (e.g. `"rule_abc"`, `rules=["rule_1"]`) are constructed
via `model_construct(...)` to bypass Pydantic's structural pattern — those
tests target the *validator's* rejection logic, not Pydantic's.
"""
from __future__ import annotations

import pytest

from src.usecases.step_4_telemetry.models.sigma_logsource import SigmaLogsource
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeatures,
    DetectionAxis,
    TargetEnvironment,
    TelemetryPlan,
)
from src.usecases.step_6_generate_sigma.models.correlation import (
    Correlation,
    CorrelationBody,
    CorrelationReasoning,
    CorrelationRule,
)
from src.usecases.step_6_generate_sigma.models.detection import (
    Detection,
    DetectionBody,
    DetectionRule,
    LogsourceRef,
    SelectedField,
)
from src.usecases.step_6_generate_sigma.models.result import Step6Result
from src.usecases.step_6_generate_sigma.validators import (
    Step6ValidationError,
    Step6Validator,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _make_plan_with(extra_ls: list[SigmaLogsource] | None = None) -> TelemetryPlan:
    """TelemetryPlan with the 5 standard logsources + optional extras."""
    ls = [
        SigmaLogsource(category="webserver", product=None, allowed_fields={
            "cs-uri-query": ["contains"],
            "dns.question.name": [],  # [] = "không cần modifier"
        }),
        SigmaLogsource(category="process_creation", product="windows", allowed_fields={
            "CommandLine": ["contains", "endswith"],
            "Image": ["endswith"],
        }),
        SigmaLogsource(category="network_connection", product="windows", allowed_fields={
            "DestinationPort": ["equals"],
        }),
    ]
    if extra_ls:
        ls.extend(extra_ls)
    return TelemetryPlan(
        cve_id="CVE-TEST",
        target_environment=TargetEnvironment(platforms=["windows"]),
        detection_axis=DetectionAxis(primary="initial_access"),
        detection_strategy="test",
        correlation_required=True,
        candidate_features=CandidateFeatures(),
        sigma_logsources=ls,
        telemetry_gaps=[],
        gap_severity="medium",
        telemetry_confidence=0.9,
    )


def _det(
    det_id: str,
    category: str,
    product: str | None,
    selections: list[SelectedField],
    *,
    bypass_pydantic: bool = False,
) -> Detection:
    """Build a Detection.

    Schema v9: `Detection` carries NO `reasoning` field. Per-selection
    reasoning lives inline in each `SelectedField.reason` — built here by
    attaching `reason=None` (the default), or whatever the caller set on
    the `SelectedField` objects directly.

    `bypass_pydantic=True` uses `model_construct(...)` to skip structural
    validation — needed when testing the validator's rejection of inputs that
    Pydantic would also reject (e.g. `"rule_abc"`).
    """
    rule = DetectionRule(
        description=f"test {det_id}",
        logsource=LogsourceRef(category=category, product=product),
        detection=DetectionBody(selection=selections),
        level="high",
    )
    if bypass_pydantic:
        return Detection.model_construct(id=det_id, rule=rule)
    return Detection(id=det_id, rule=rule)


def _result(detections: list[Detection], correlations: list[Correlation] | None = None,
             reasoning: str = "ok") -> Step6Result:
    return Step6Result(
        cve_id="CVE-TEST",
        detections=detections,
        correlations=correlations or [],
        reasoning=reasoning,
        ai_model="test",
    )


def _sel(name: str, modifier: str | None, value: str) -> SelectedField:
    return SelectedField(name=name, modifier=modifier, value=value)


def _corr(refs: list[str], corr_type: str = "temporal", window: str | None = "5m",
          *, bypass_pydantic: bool = False) -> Correlation:
    body = CorrelationBody.model_construct(
        rules=refs, type=corr_type, window=window,
    ) if bypass_pydantic else CorrelationBody(rules=refs, type=corr_type, window=window)
    return Correlation(
        rule=CorrelationRule(
            description="test corr",
            correlation=body,
            level="high",
        ),
        reasoning=CorrelationReasoning(correlation_strategy="test"),
    )


# ---------------------------------------------------------------------------
# 1. Detection ID format
# ---------------------------------------------------------------------------


class TestDetectionIdFormat:
    def test_valid_rule_1_accepted(self):
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "${jndi:")])
        Step6Validator(plan).validate(_result([det]))  # no raise

    def test_free_text_name_rejected(self):
        plan = _make_plan_with()
        det = _det("webserver_jndi", "webserver", None, [_sel("cs-uri-query", "contains", "${jndi:")],
                   bypass_pydantic=True)
        with pytest.raises(Step6ValidationError, match="does not match required pattern"):
            Step6Validator(plan).validate(_result([det]))

    def test_rule_zero_rejected(self):
        """`rule_0` is forbidden by validator (leading-zero) — even though Pydantic's
        pattern `^rule_[0-9]+$` would accept it. Test the validator's tighter rule."""
        plan = _make_plan_with()
        det = _det("rule_0", "webserver", None, [_sel("cs-uri-query", "contains", "${jndi:")])
        with pytest.raises(Step6ValidationError, match="does not match required pattern"):
            Step6Validator(plan).validate(_result([det]))

    def test_rule_abc_rejected(self):
        plan = _make_plan_with()
        det = _det("rule_abc", "webserver", None, [_sel("cs-uri-query", "contains", "${jndi:")],
                   bypass_pydantic=True)
        with pytest.raises(Step6ValidationError, match="does not match required pattern"):
            Step6Validator(plan).validate(_result([det]))

    def test_rule_10_accepted(self):
        plan = _make_plan_with()
        det = _det("rule_10", "webserver", None, [_sel("cs-uri-query", "contains", "${jndi:")])
        Step6Validator(plan).validate(_result([det]))  # no raise


# ---------------------------------------------------------------------------
# 2. Detection ID uniqueness
# ---------------------------------------------------------------------------


class TestDetectionIdUniqueness:
    def test_distinct_ids_accepted(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_2", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "y")])
        Step6Validator(plan).validate(_result([d1, d2]))  # no raise

    def test_duplicate_id_rejected(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_1", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "y")])
        with pytest.raises(Step6ValidationError, match="duplicates an earlier detection"):
            Step6Validator(plan).validate(_result([d1, d2]))


# ---------------------------------------------------------------------------
# 3. Per-logsource uniqueness
# ---------------------------------------------------------------------------


class TestPerLogsourceUniqueness:
    def test_same_logsource_rejected(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_2", "webserver", None, [_sel("cs-uri-query", "contains", "y")])
        with pytest.raises(Step6ValidationError, match="duplicates an earlier detection"):
            Step6Validator(plan).validate(_result([d1, d2]))

    def test_same_category_different_product_accepted(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "x")])
        d2 = _det("rule_2", "network_connection", "windows",
                  [_sel("DestinationPort", "equals", "389")])
        Step6Validator(plan).validate(_result([d1, d2]))  # no raise


# ---------------------------------------------------------------------------
# 4. Search-space respect
# ---------------------------------------------------------------------------


class TestSearchSpaceRespect:
    def test_invented_category_rejected(self):
        plan = _make_plan_with()
        det = _det("rule_1", "dns_query", None, [_sel("question", "contains", "x")])
        with pytest.raises(Step6ValidationError, match="not in Step 4 search space"):
            Step6Validator(plan).validate(_result([det]))

    def test_invented_product_rejected(self):
        plan = _make_plan_with()
        det = _det("rule_1", "process_creation", "macos",
                   [_sel("CommandLine", "contains", "x")])
        with pytest.raises(Step6ValidationError, match="not in Step 4 search space"):
            Step6Validator(plan).validate(_result([det]))

    def test_invented_field_rejected(self):
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("evil-field", "contains", "x")])
        with pytest.raises(Step6ValidationError, match="not in allowed_fields"):
            Step6Validator(plan).validate(_result([det]))

    def test_invented_modifier_rejected(self):
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "regex", "x")])
        with pytest.raises(Step6ValidationError, match="modifier 'regex' not in allowed_fields"):
            Step6Validator(plan).validate(_result([det]))

    def test_modifier_required_on_non_empty_field(self):
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("cs-uri-query", None, "x")])
        with pytest.raises(Step6ValidationError, match="requires a modifier"):
            Step6Validator(plan).validate(_result([det]))

    def test_modifier_none_allowed_on_empty_field_list(self):
        """`dns.question.name` has allowed_fields[field] = [] → modifier None is OK."""
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("dns.question.name", None, "evil.com")])
        Step6Validator(plan).validate(_result([det]))  # no raise

    def test_modifier_set_on_empty_field_list_rejected(self):
        """Field with allowed_fields[field] = [] doesn't accept a modifier either."""
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("dns.question.name", "contains", "x")])
        with pytest.raises(Step6ValidationError, match="modifier 'contains' not in allowed_fields"):
            Step6Validator(plan).validate(_result([det]))


# ---------------------------------------------------------------------------
# 5. Value is NOT enforced
# ---------------------------------------------------------------------------


class TestValueNotEnforced:
    def test_any_value_string_passes_validator(self):
        """Value is AI's semantic knowledge — validator does NOT inspect it."""
        plan = _make_plan_with()
        det = _det(
            "rule_1", "webserver", None,
            [_sel("cs-uri-query", "contains", "any-arbitrary-evidence-based-string-here")],
        )
        Step6Validator(plan).validate(_result([det]))  # no raise

    def test_unrelated_value_still_passes_validator(self):
        """Even a clearly unrelated value (e.g. "powershell" for Log4Shell) passes
        the validator — it is the prompt's job to enforce evidence-based values."""
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "powershell")])
        Step6Validator(plan).validate(_result([det]))  # no raise (value not checked)


# ---------------------------------------------------------------------------
# 6. Correlation refs resolve
# ---------------------------------------------------------------------------


class TestCorrelationResolve:
    def test_valid_refs_accepted(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_2", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "y")])
        corr = _corr(["rule_1", "rule_2"])
        Step6Validator(plan).validate(_result([d1, d2], [corr]))  # no raise

    def test_ghost_ref_rejected(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_2", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "y")])
        corr = _corr(["rule_1", "rule_99"])
        with pytest.raises(Step6ValidationError, match="'rule_99' does not match any detections"):
            Step6Validator(plan).validate(_result([d1, d2], [corr]))

    def test_single_ref_rejected(self):
        """Validator rejects < 2 refs even though Pydantic would also reject.
        We bypass Pydantic via model_construct to verify the validator's check."""
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        d2 = _det("rule_2", "process_creation", "windows",
                  [_sel("CommandLine", "contains", "y")])
        corr = _corr(["rule_1"], bypass_pydantic=True)
        with pytest.raises(Step6ValidationError, match="requires >= 2 detection.id refs"):
            Step6Validator(plan).validate(_result([d1, d2], [corr]))


# ---------------------------------------------------------------------------
# 7. Correlation requires ≥ 2 detections
# ---------------------------------------------------------------------------


class TestCorrelationRequiresMinDetections:
    def test_correlation_with_one_detection_rejected(self):
        plan = _make_plan_with()
        d1 = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        corr = _corr(["rule_1", "rule_2"], bypass_pydantic=True)
        # The `< 2 detections` check fires first (more fundamental).
        with pytest.raises(Step6ValidationError, match="require >= 2 detections"):
            Step6Validator(plan).validate(_result([d1], [corr]))

    def test_empty_correlations_no_op(self):
        """No correlations → no correlation validation runs."""
        plan = _make_plan_with()
        det = _det("rule_1", "webserver", None, [_sel("cs-uri-query", "contains", "x")])
        Step6Validator(plan).validate(_result([det], correlations=[]))  # no raise


# ---------------------------------------------------------------------------
# Sanity: Pydantic structural vs validator business separation
# ---------------------------------------------------------------------------


class TestValidatorIndependentOfPydantic:
    def test_structurally_valid_but_semantically_violating_passes_pydantic(self):
        """`Step6Result.model_validate(...)` does NOT check search space — only
        the validator does. This is the architect v9 separation contract."""
        # Invent a category + field NOT in the search space.
        det = _det("rule_1", "ghost_category", None, [_sel("ghost_field", "contains", "x")])
        result = _result([det])
        # Pydantic accepts (structural only):
        assert Step6Result.model_validate(result.model_dump()) == result
        # Validator rejects:
        plan = _make_plan_with()
        with pytest.raises(Step6ValidationError, match="not in Step 4 search space"):
            Step6Validator(plan).validate(result)


# ---------------------------------------------------------------------------
# Error aggregation: multiple violations reported in one exception
# ---------------------------------------------------------------------------


class TestErrorAggregation:
    def test_multiple_violations_collected(self):
        plan = _make_plan_with()
        # 2 invented fields on same detection
        det = _det("rule_1", "webserver", None, [
            _sel("ghost-field-a", "contains", "x"),
            _sel("ghost-field-b", "contains", "y"),
        ])
        with pytest.raises(Step6ValidationError) as excinfo:
            Step6Validator(plan).validate(_result([det]))
        msg = str(excinfo.value)
        assert "ghost-field-a" in msg
        assert "ghost-field-b" in msg
