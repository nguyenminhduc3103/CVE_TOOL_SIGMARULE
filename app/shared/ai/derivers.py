"""Single source of truth cho attack_flow fields derivation."""
from __future__ import annotations

from typing import Any

_ENTRY_VECTOR_MAP = {
    'remote_network': 'network', 'remote': 'network',
    'adjacent_network': 'adjacent_network', 'local': 'local', 'physical': 'physical',
}
_EXECUTION_MECHANISM_MAP = {
    'deserialization': 'unsafe_object_materialization',
    'path_traversal': 'path_resolution_bypass',
    'information_disclosure': 'path_resolution_bypass',
    'privilege_escalation': 'privilege_boundary_escape',
    'command_injection': 'command_execution',
    'code_injection': 'code_injection',
    'webshell_drop': 'webshell_drop',
    'file_upload': 'file_upload',
    'ssrf': 'server_side_request_forgery',
    'sql_injection': 'sql_injection',
    'auth_bypass': 'authentication_bypass',
    'remote_code_execution': 'arbitrary_code_execution',
}
_EFFECT_MAP = {
    'process_creation': 'Process creation', 'file_write': 'File write',
    'network_callback': 'Network callback', 'network_connection': 'Network connection',
    'public_facing_exploit': 'Public-facing exploit attempt',
    'web_request': 'Web request', 'registry_modification': 'Registry modification',
    'image_load': 'Image/DLL load', 'privilege_escalation': 'Privilege escalation',
    'webshell_drop': 'Webshell drop', 'file_read': 'File read',
    'tool_download': 'Tool download',
}

def _coerce_vc(vc):
    if not vc: return None
    text = str(vc).strip().lower()
    if text.startswith('vulnerabilityclass.'):
        text = text[len('vulnerabilityclass.'):]
    return text or None

def derive_entry_vector(exploit_vector):
    ev = (exploit_vector or 'unknown').lower().strip()
    return _ENTRY_VECTOR_MAP.get(ev, ev or 'unknown')

def derive_execution_mechanism(vulnerability_class):
    vc = _coerce_vc(vulnerability_class)
    if not vc: return 'unknown'
    return _EXECUTION_MECHANISM_MAP.get(vc, vc)

def derive_observable_side_effects(mandatory_behaviors):
    behaviors = mandatory_behaviors or []
    return [_EFFECT_MAP.get(b, b.replace('_', ' ')) for b in behaviors]

def derive_attack_flow(exploit_vector=None, vulnerability_class=None, mandatory_behaviors=None):
    return {
        'entry_vector': derive_entry_vector(exploit_vector),
        'execution_mechanism': derive_execution_mechanism(vulnerability_class),
        'observable_side_effects': derive_observable_side_effects(mandatory_behaviors),
    }

def fill_missing_attack_flow(current, exploit_vector=None, vulnerability_class=None, mandatory_behaviors=None):
    derived = derive_attack_flow(exploit_vector, vulnerability_class, mandatory_behaviors)
    cur = current or {}
    return {
        'entry_vector': cur.get('entry_vector') or derived['entry_vector'],
        'execution_mechanism': cur.get('execution_mechanism') or derived['execution_mechanism'],
        'observable_side_effects': (
            cur.get('observable_side_effects') if cur.get('observable_side_effects')
            else derived['observable_side_effects']
        ),
    }
