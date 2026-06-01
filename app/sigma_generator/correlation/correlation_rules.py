from __future__ import annotations

# Đã sửa đổi để hỗ trợ chuẩn Multi-event Correlation
FAMILY_CORRELATION_RULES: dict[str, dict[str, object]] = {
    "spring4shell": {
        "required_selections": ["selection_http", "selection_process"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "5m",
        "reasoning": "Public-facing exploit followed by process execution.",
    },
    "jndi_injection": {
        "required_selections": ["selection_jndi", "selection_network"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "1m",
        "reasoning": "JNDI lookup triggering outbound network activity.",
    },
    "log4shell": {
        "required_selections": ["selection_jndi", "selection_network"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "1m",
        "reasoning": "JNDI lookup triggering outbound network activity.",
    },
    "printnightmare": {
        "required_selections": ["selection_spoolsv", "selection_dll"],
        "is_cross_event": False, 
        "expression": "selection_spoolsv and selection_dll", # Có thể nằm cùng 1 event (ImageLoaded)
        "reasoning": "DLL load from spoolsv.exe is the primary exploitation chain.",
    },
    "struts_ognl": {
        "required_selections": ["selection_http", "selection_process"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "5m",
        "reasoning": "Public-facing exploit followed by process execution.",
    },
    "apache_path_traversal": {
        "required_selections": ["selection_http", "selection_file"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "5m",
        "reasoning": "Web request leads to file access or file disclosure.",
    },
    "file_upload": {  # Thêm cụm này cho Webshell (CVE-2025-22723)
        "required_selections": ["selection_file", "selection_process"],
        "is_cross_event": True,
        "correlation_type": "temporal_ordered",
        "timespan": "5m",
        "reasoning": "File drop in webroot followed by process execution (Webshell).",
    }
}

BEHAVIOR_TO_SELECTION: dict[str, str] = {
    "process_creation": "selection_process",
    "network_connection": "selection_network",
    "web_request": "selection_http",
    "tool_download": "selection_download",
    "network_callback": "selection_callback",
    "file_write": "selection_file",
    "file_read": "selection_file",
}