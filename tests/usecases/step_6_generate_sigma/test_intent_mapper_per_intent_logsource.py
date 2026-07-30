"""Intent Mapper — verify per-intent logsource resolution and family threading.

Before the fix, ``_pick_logsource`` called ``map_all_intents`` WITHOUT
``family_signature``/``family``, so family KB matching could not occur.
After the fix, the kwargs are threaded and per-intent logsource selection
is possible.
"""
from __future__ import annotations

from unittest.mock import patch

from src.usecases.step_6_generate_sigma.domain.detection_plan import (
    DetectionIntent,
    DetectionLogic,
    DetectionPlan,
)


def _build_plan():
    return DetectionPlan(
        detections=[
            DetectionIntent(intent="jndi_payload_lookup"),
            DetectionIntent(intent="outbound_ldap_rmi"),
        ],
        logic=DetectionLogic(operator="at_least", operands=[0, 1], threshold=1),
    )


def test_pick_logsource_threads_family_signature(log4shell_telemetry):
    """``_pick_logsource`` must pass ``family_signature``/``family`` through."""
    from src.usecases.step_6_generate_sigma.builders import sigma_builder

    plan = _build_plan()
    # Patch where the function is *called* from (sigma_builder imported the
    # binding via `from ... import map_all_intents`).
    with patch(
        "src.usecases.step_6_generate_sigma.builders.sigma_builder.map_all_intents",
        return_value=[],
    ) as mocked:
        sigma_builder._pick_logsource(
            plan, log4shell_telemetry, family_signature="log4shell", family="log4shell",
        )
        assert mocked.called
        call_args = mocked.call_args.args
        # Signature: map_all_intents(intents, telemetry, family_signature, family)
        assert len(call_args) >= 4, f"Expected 4 positional args, got {len(call_args)}"
        assert call_args[2] == "log4shell", f"family_signature={call_args[2]!r}"
        assert call_args[3] == "log4shell", f"family={call_args[3]!r}"


def test_map_all_intents_resolves_log4shell_intents(log4shell_telemetry):
    """With the KB enriched, ``map_all_intents`` should resolve both Log4Shell
    intents to their respective logsources via per-intent ``domain_hint``."""
    from src.usecases.step_6_generate_sigma._knowledge import loader
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        map_all_intents,
    )

    loader.invalidate_cache()
    plan = _build_plan()
    resolutions = map_all_intents(
        plan.detections, log4shell_telemetry,
        family_signature="log4shell", family="log4shell",
    )

    by_slug = {str(r.intent): r for r in resolutions}
    jndi = by_slug["jndi_payload_lookup"]
    outbound = by_slug["outbound_ldap_rmi"]

    assert jndi.resolved, "jndi_payload_lookup should resolve"
    assert jndi.domain_hint == "http"
    assert jndi.canonical_logsource is not None
    assert jndi.canonical_logsource["category"] == "webserver"

    assert outbound.resolved, "outbound_ldap_rmi should resolve"
    assert outbound.domain_hint == "network"
    assert outbound.canonical_logsource is not None
    assert outbound.canonical_logsource["category"] == "network_connection"


def test_pick_logsource_for_intent_selects_per_intent(log4shell_telemetry):
    """``_pick_logsource_for_intent`` must pick the matching per-intent resolution
    rather than the first one or ``sigma_logsources[0]``."""
    from src.usecases.step_6_generate_sigma.builders.sigma_builder import (
        _pick_logsource_for_intent,
    )
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        map_all_intents,
    )

    plan = _build_plan()
    resolutions = map_all_intents(
        plan.detections, log4shell_telemetry,
        family_signature="log4shell", family="log4shell",
    )

    ls0 = _pick_logsource_for_intent("jndi_payload_lookup", resolutions, log4shell_telemetry, plan)
    ls1 = _pick_logsource_for_intent("outbound_ldap_rmi", resolutions, log4shell_telemetry, plan)

    assert ls0["category"] == "webserver"
    assert ls1["category"] == "network_connection"
    assert ls0 != ls1, "per-intent logsources must differ"


def test_ai_free_text_intent_resolves_via_keyword_match(log4shell_telemetry):
    """Real-world AI emits descriptive intent text, not KB slugs.
    The IntentMapper must match via keyword/alias, not require exact slug.
    """
    from src.usecases.step_6_generate_sigma.domain.detection_plan import (
        DetectionIntent,
        DetectionLogic,
        DetectionPlan,
    )
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        map_all_intents,
    )

    plan = DetectionPlan(
        detections=[
            DetectionIntent(intent="suspicious jndi lookup injection in web request parameters or headers"),
            DetectionIntent(intent="outbound directory service callback connection"),
            DetectionIntent(intent="suspicious child process spawn from application server"),
        ],
        logic=DetectionLogic(operator="any", operands=[0, 1, 2]),
    )

    # Caller used the AI-provided family 'jndi_injection' which is an alias for log4shell.
    resolutions = map_all_intents(
        plan.detections, log4shell_telemetry,
        family_signature="jndi_injection", family="jndi_injection",
    )

    categories = [r.canonical_logsource["category"] for r in resolutions if r.canonical_logsource]
    assert "webserver" in categories, f"jndi lookup should map to webserver, got {categories}"
    assert "network_connection" in categories, (
        f"LDAP callback should map to network_connection, got {categories}"
    )


def test_family_alias_resolves_jndi_injection_to_log4shell(log4shell_telemetry):
    """``jndi_injection`` should be an alias for ``log4shell`` family KB."""
    from src.usecases.step_6_generate_sigma._knowledge import loader
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        _resolve_family,
    )

    loader.invalidate_cache()
    entry, resolved_name = _resolve_family("jndi_injection", None)
    assert entry is not None, "jndi_injection should resolve via alias"
    assert resolved_name == "log4shell"


def test_family_resolves_descriptive_signature_via_keyword():
    """Step 2 AI emits descriptive signatures like ``'apache log4j2 jndi rce (log4shell)'``.
    The resolver must still find ``log4shell`` via keyword overlap with aliases.
    """
    from src.usecases.step_6_generate_sigma._knowledge import loader
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        _resolve_family,
    )

    loader.invalidate_cache()

    for sig in [
        "apache log4j2 jndi rce (log4shell)",
        "apache log4j2 jndi rce",
        "log4j2 jndi rce",
        "log4j2 rce",
        "log4j jndi rce",
        "log4j rce",
    ]:
        entry, name = _resolve_family(sig, None)
        assert entry is not None, f"{sig!r} should resolve to log4shell family"
        assert name == "log4shell", f"{sig!r} -> {name}"


def test_family_resolves_unrelated_signature_as_none():
    """A truly unrelated signature must NOT resolve to any family (avoid
    false-positive mapping).
    """
    from src.usecases.step_6_generate_sigma._knowledge import loader
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        _resolve_family,
    )

    loader.invalidate_cache()
    # These have no overlap with log4shell/spring4shell/printnightmare keywords.
    for sig in [
        "random_sql_injection_signature",
        "totally_unrelated_exploit",
        "memory_corruption_vuln",
    ]:
        entry, name = _resolve_family(sig, None)
        assert entry is None, f"{sig!r} unexpectedly resolved to {name}"


def test_sparse_step4_logsources_dont_block_domain_hint():
    """Regression: when Step 4 emits only ``process_creation`` but the family KB
    intent has ``domain_hint: network``, the mapper must still produce a
    ``network_connection`` logsource (not silently collapse to
    ``process_creation``).
    """
    from src.usecases.step_6_generate_sigma.domain.detection_plan import (
        DetectionIntent,
        DetectionLogic,
        DetectionPlan,
    )
    from src.usecases.step_6_generate_sigma.services.intent_mapper import (
        map_all_intents,
    )

    plan = DetectionPlan(
        detections=[
            DetectionIntent(intent="jndi injection payload attempt in web requests or headers"),
            DetectionIntent(intent="outbound network callback to directory services or remote class loading ports"),
        ],
        logic=DetectionLogic(operator="any", operands=[0, 1]),
    )

    # Step 4 only emitted process_creation telemetry — sparse.
    sparse = {
        "sigma_logsources": [{"category": "process_creation", "product": "windows"}],
        "validated_fields": ["Image", "CommandLine"],
    }

    resolutions = map_all_intents(
        plan.detections, sparse,
        family_signature="jndi_injection", family="jndi_injection",
    )

    cats = [r.canonical_logsource["category"] for r in resolutions]
    assert "webserver" in cats, f"jndi lookup should still produce webserver; got {cats}"
    assert "network_connection" in cats, (
        f"outbound intent should still produce network_connection even when "
        f"Step 4 only emits process_creation; got {cats}"
    )
