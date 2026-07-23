from __future__ import annotations


def select_detection_axis(behaviors: list[str], logsources: list[str], techniques: list[str] | None) -> tuple[list[str], float]:
    axis_map = {
        "pre_exploit": "pre-exploit",
        "post_exploit": "post-exploit",
        "process_creation": "process",
        "webserver": "web",
        "network_connection": "network",
        "file_event": "post-exploit",
        "registry_event": "post-exploit",
        "image_load": "post-exploit",
    }
    axes: list[str] = []

    if "public_facing_exploit" in behaviors or "web_request" in behaviors:
        axes.append("pre-exploit")
    if any(behavior in behaviors for behavior in ("process_creation", "file_write", "registry_modification", "image_load", "webshell_drop")):
        axes.append("post-exploit")

    for logsource in logsources:
        axis = axis_map.get(logsource)
        if axis and axis not in axes:
            axes.append(axis)

    confidence = 0.35 + (0.18 * len(logsources)) + (0.08 * len(behaviors))
    if techniques:
        confidence += 0.1
    confidence = min(confidence, 0.95)

    return axes, round(confidence, 2)
