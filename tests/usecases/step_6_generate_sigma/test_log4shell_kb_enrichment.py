"""KB enrichment tests — verify the Log4Shell KB entry has domain_hint per intent,
obfuscation markers, and the outbound_ports signature block."""
from __future__ import annotations


def test_log4shell_family_has_per_intent_domain_hint():
    from src.usecases.step_6_generate_sigma._knowledge import loader

    loader.invalidate_cache()
    family = loader.get_family("log4shell")
    assert family is not None

    intent_by_name = {
        str(i.get("intent", "")): i for i in family.get("intents", []) or []
    }

    assert "jndi_payload_lookup" in intent_by_name
    assert intent_by_name["jndi_payload_lookup"].get("domain_hint") == "http"

    assert "outbound_ldap_rmi" in intent_by_name
    assert intent_by_name["outbound_ldap_rmi"].get("domain_hint") == "network"


def test_log4shell_payload_markers_include_obfuscation():
    from src.usecases.step_6_generate_sigma._knowledge import loader

    loader.invalidate_cache()
    sig = loader.get_signature("log4shell.payload_markers")
    assert sig is not None
    markers = sig.get("markers", [])
    assert "jndi:" in markers
    # Obfuscation variants the planner should be aware of
    for variant in (
        "${${lower:j}ndi:",
        "${${::-j}${::-n}${::-d}${::-i}:",
        "${jndi:ldap:",
        "${jndi:rmi:",
    ):
        assert variant in markers, f"missing obfuscation marker: {variant}"


def test_log4shell_outbound_ports_signature_present():
    from src.usecases.step_6_generate_sigma._knowledge import loader

    loader.invalidate_cache()
    sig = loader.get_signature("log4shell.outbound_ports")
    assert sig is not None
    ports = sig.get("ports", [])
    # LDAP family
    for port in (389, 636, 3268, 3269, 1389):
        assert port in ports, f"missing LDAP port: {port}"
    # RMI / IIOP
    for port in (1099, 1059, 1100):
        assert port in ports, f"missing RMI/IIOP port: {port}"
    # DNS callback
    assert 53 in ports


def test_spring4shell_and_printnightmare_get_domain_hint():
    """Regression: other multi-intent families should also resolve correctly."""
    from src.usecases.step_6_generate_sigma._knowledge import loader

    loader.invalidate_cache()

    spring = loader.get_family("spring4shell")
    assert spring is not None
    spring_intents = {
        str(i.get("intent", "")): i for i in spring.get("intents", []) or []
    }
    assert spring_intents["classloader_exploit_request"].get("domain_hint") == "http"
    assert spring_intents["post_exploit_command_execution"].get("domain_hint") == "process"

    pn = loader.get_family("printnightmare")
    assert pn is not None
    pn_intents = {
        str(i.get("intent", "")): i for i in pn.get("intents", []) or []
    }
    assert pn_intents["spoolsv_dll_load"].get("domain_hint") == "process"
