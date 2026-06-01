from __future__ import annotations

from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.telemetry import TelemetryAssessment
from app.sigma_generator.family_detection.base import DetectionTemplate
from app.sigma_generator.models.sigma_detection import SigmaDetection


class _BaseTemplate(DetectionTemplate):
    def _get(self, value: object | None, key: str) -> object | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(key)
        return getattr(value, key, None)

    def _list(self, value: object | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value if item is not None]

    def _normalize(self, value: object | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower().replace(".", "_").replace("-", "_")
        return text or None

    def _validated_fields(self, telemetry: TelemetryAssessment | dict[str, object] | None) -> set[str]:
        return {str(item) for item in self._list(self._get(telemetry, "validated_fields"))}

    def _field_allowed(self, telemetry: TelemetryAssessment | dict[str, object] | None, field_expression: str) -> bool:
        validated_fields = self._validated_fields(telemetry)
        if not validated_fields:
            return False
        base_field = field_expression.split("|", 1)[0]
        return base_field in validated_fields

    def _selection(self, telemetry: TelemetryAssessment | dict[str, object] | None, field_expression: str, values: list[str]) -> dict[str, list[str]] | None:
        if not self._field_allowed(telemetry, field_expression):
            return None
        return {field_expression: values}

    def _build_detection(self, selections: dict[str, dict[str, list[str]]], condition: str) -> SigmaDetection:
        return SigmaDetection(selections=selections, condition=condition)


class Log4ShellTemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return self._normalize(signature) == "log4shell"

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        selections: dict[str, dict[str, list[str]]] = {}
        for name, field_expression, values in (
            ("selection_jndi", "CommandLine|contains", ["jndi:", "ldap://", "rmi://"]),
            ("selection_network", "DestinationHostname|contains", ["${EXTERNAL_HOST}"]),
            ("selection_download", "CommandLine|contains", ["curl ", "wget "]),
        ):
            selection = self._selection(telemetry, field_expression, values)
            if selection is not None:
                selections[name] = selection
        return self._build_detection(selections, "1 of selection_*")


class Spring4ShellTemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return self._normalize(family) == "spring4shell"

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        selections: dict[str, dict[str, list[str]]] = {}
        for name, field_expression, values in (
            ("selection_http", "cs-uri-query|contains", ["class.module.classLoader", "classLoader.resources.context.parent.pipeline"]),
            ("selection_process", "CommandLine|contains", ["cmd.exe", "/bin/sh"]),
        ):
            selection = self._selection(telemetry, field_expression, values)
            if selection is not None:
                selections[name] = selection
        return self._build_detection(selections, "1 of selection_*")


class PrintNightmareTemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return self._normalize(signature) == "printnightmare"

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        selections: dict[str, dict[str, list[str]]] = {}
        for name, field_expression, values in (
            ("selection_dll", "ImageLoaded|contains", [".dll"]),
            ("selection_spoolsv", "ParentImage|endswith", ["spoolsv.exe"]),
        ):
            selection = self._selection(telemetry, field_expression, values)
            if selection is not None:
                selections[name] = selection
        return self._build_detection(selections, "all of selection_*")


class StrutsOgnlTemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return self._normalize(signature) == "struts_ognl"

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        selections: dict[str, dict[str, list[str]]] = {}
        selection = self._selection(telemetry, "cs-uri-query|contains", ["%{", "#context", "@java.lang"])
        if selection is not None:
            selections["selection_ognl"] = selection
        return self._build_detection(selections, "selection_ognl")


class ApachePathTraversalTemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return self._normalize(signature) == "apache_path_traversal"

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        selections: dict[str, dict[str, list[str]]] = {}
        selection = self._selection(telemetry, "cs-uri-query|contains", ["../", "..%2f", "..\\"])
        if selection is not None:
            selections["selection_path"] = selection
        return self._build_detection(selections, "selection_path")


class GenericRCETemplate(_BaseTemplate):
    def supports(self, family: str | None, signature: str | None) -> bool:
        return True

    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        behaviors = self._list(self._get(analysis, "mandatory_behaviors"))
        behavior_map: dict[str, tuple[str, str, str]] = {
            "web_request": ("selection_http", "cs-uri-query|contains", "${IOC}"),
            "process_creation": ("selection_process", "CommandLine|contains", "${PAYLOAD}"),
            "network_connection": ("selection_network", "DestinationHostname|contains", "${C2}"),
            "network_callback": ("selection_callback", "DestinationHostname|contains", "${C2}"),
            "tool_download": ("selection_download", "CommandLine|contains", "${PAYLOAD}"),
            "public_facing_exploit": ("selection_http", "cs-uri-query|contains", "${IOC}"),
            "file_write": ("selection_file", "TargetFilename|contains", "${IOC}"),
            "file_read": ("selection_file", "TargetFilename|contains", "${IOC}"),
        }
        selections: dict[str, dict[str, list[str]]] = {}
        for behavior in behaviors:
            mapping = behavior_map.get(behavior)
            if not mapping:
                continue
            selection_name, field_expression, placeholder = mapping
            
            # SỬA Ở ĐÂY: Phải check xem field_expression này có HỢP LỆ với logsource hiện tại không
            # Nếu telemetry đang là process_creation, nó sẽ block TargetFilename của file_write
            if self._field_allowed(telemetry, field_expression): 
                selection = self._selection(telemetry, field_expression, [placeholder])
                if selection is not None:
                    selections[selection_name] = selection

        if selections:
            return self._build_detection(selections, "1 of selection_*")

        candidate_logsources = self._list(self._get(telemetry, "candidate_logsources"))
        primary_logsource = candidate_logsources[0] if candidate_logsources else None
        if primary_logsource == "process_creation" and self._field_allowed(telemetry, "CommandLine|contains"):
            return self._build_detection({"selection_process": {"CommandLine|contains": ["${PAYLOAD}"]}}, "1 of selection_*")
        if primary_logsource == "webserver" and self._field_allowed(telemetry, "cs-uri-query|contains"):
            return self._build_detection({"selection_http": {"cs-uri-query|contains": ["${IOC}"]}}, "1 of selection_*")
        if primary_logsource == "network_connection" and self._field_allowed(telemetry, "DestinationHostname|contains"):
            return self._build_detection({"selection_network": {"DestinationHostname|contains": ["${C2}"]}}, "1 of selection_*")
        if primary_logsource == "file_event" and self._field_allowed(telemetry, "TargetFilename|contains"):
            return self._build_detection({"selection_file": {"TargetFilename|contains": ["${IOC}"]}}, "1 of selection_*")
        if self._field_allowed(telemetry, "EventID|contains"):
            return self._build_detection({"selection_generic": {"EventID|contains": ["${IOC}"]}}, "1 of selection_*")
        return self._build_detection({}, "1 of selection_*")