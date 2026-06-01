from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.coverage import CoverageAssessment
from app.models.core import CoreCVEData
from app.models.telemetry import TelemetryAssessment
from app.sigma_generator.correlation.correlation_builder import CorrelationBuilder
from app.sigma_generator.correlation.correlation_rules import FAMILY_CORRELATION_RULES
from app.sigma_generator.family_detection.builder import FamilyDetectionBuilder
from app.sigma_generator.models.sigma_detection import SigmaDetection
from app.sigma_generator.models.sigma_metadata import SigmaMetadata
from app.sigma_generator.models.sigma_rule import SigmaRule


class SigmaRuleGenerator:
    def __init__(self, output_dir: str | Path = "generated_rules") -> None:
        self.output_dir = Path(output_dir)
        self.detection_builder = FamilyDetectionBuilder()
        self.correlation_builder = CorrelationBuilder()
        self._pending_correlation = None  # Biến tạm để giữ block correlation

    def generate(
        self,
        core: CoreCVEData,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
        coverage: CoverageAssessment | dict[str, object] | None,
    ) -> list[SigmaRule] | SigmaRule:
        cve_id = self._get(core, "cve_id") or "CVE-UNKNOWN"
        analysis_confidence = self._float(self._get(analysis, "analysis_confidence") or self._get(analysis, "confidence"))

        family = self._normalize_slug(self._get(analysis, "family"))
        signature = self._normalize_slug(self._get(analysis, "signature")) or self._signature_from_reasoning(analysis)
        title = self._generate_title(core, analysis, family, signature)
        description = self._generate_description(core, analysis, attack)

        references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
        tags = self._build_tags(attack)
        level = self._severity_to_level(self._float(self._get(core, "cvss_score")), self._get(core, "severity"))
        status = self._coverage_to_status(self._get(coverage, "decision"))
        related = self._build_related(coverage)

        primary_logsource, secondary_logsources = self._select_logsources(telemetry)
        
        # 1. Khởi tạo Detection ban đầu
        detection = self.detection_builder.build(analysis, attack, telemetry)
        self._fill_detection_keywords(detection, analysis, core)
        
        # 2. Lấy Logic Correlation
        correlation = self.correlation_builder.build(analysis, attack, telemetry, detection)
        detection_confidence = self._adjust_confidence(analysis_confidence, telemetry, family, signature, getattr(correlation, "expression", "") or "")

        metadata_base = {
            "status": status,
            "description": description,
            "references": references,
            "tags": tags,
            "falsepositives": ["Unknown"],
            "level": level,
            "related": related,
        }

        is_cross_event = getattr(correlation, "is_cross_event", False)
        correlation_block = getattr(correlation, "correlation_block", None)

        # 3. NẾU LÀ CORRELATION ĐA SỰ KIỆN (CROSS-EVENT) -> Tách thành nhiều Rule
        if is_cross_event and correlation_block:
            rules_list = []
            rule_ids = []
            
            # Tách các sub-rules dựa trên selections
            for sel_name, sel_data in detection.selections.items():
                if not sel_data: continue # Bỏ qua nếu rỗng
                
                sub_title = f"{title} ({sel_name.split('_')[-1].capitalize()} Component)"
                sub_id = self._generate_rule_id(cve_id, sub_title, tags)
                rule_ids.append(sub_id)
                
                # Ánh xạ lại logsource cho đúng Taxonomy
                sub_logsource = "process_creation"
                if "file" in sel_name: sub_logsource = "file_event"
                if "http" in sel_name or "web" in sel_name: sub_logsource = "webserver"
                if "network" in sel_name: sub_logsource = "network_connection"

                sub_detection = SigmaDetection(selections={sel_name: sel_data}, condition=sel_name)
                
                sub_metadata = SigmaMetadata(title=sub_title, id=sub_id, **metadata_base)
                rules_list.append(SigmaRule(
                    metadata=sub_metadata,
                    logsource={"category": sub_logsource},
                    detection=sub_detection,
                    x_family=family or "generic",
                    x_signature=signature or family or "generic",
                    x_detection_confidence=detection_confidence,
                    x_correlation_required=False,
                    x_correlation_logic=False,
                    x_correlation_reasoning=correlation.reasoning,
                    x_secondary_logsources=[],
                ))

            # Tạo Rule Tương quan (Main Correlation Rule)
            corr_title = f"{title} (Correlation)"
            corr_id = self._generate_rule_id(cve_id, corr_title, ["correlation"])
            corr_metadata = SigmaMetadata(title=corr_title, id=corr_id, **metadata_base)
            
            # Lắp tên các sub-rule vào block correlation
            correlation_block.rules = rule_ids

            main_corr_rule = SigmaRule(
                metadata=corr_metadata,
                logsource={}, # Correlation rule không có logsource cụ thể
                detection=SigmaDetection(selections={}, condition=""), # Dummy detection
                x_family=family or "generic",
                x_signature=signature or family or "generic",
                x_detection_confidence=detection_confidence,
                x_correlation_required=True,
                x_correlation_logic=True,
                x_correlation_reasoning=correlation.reasoning,
                x_secondary_logsources=secondary_logsources,
            )
            
            # Lưu tạm vào biến class để né lỗi Pydantic
            try:
                self._pending_correlation = correlation_block.model_dump(by_alias=True, exclude_none=True)
            except AttributeError:
                self._pending_correlation = correlation_block.dict(by_alias=True, exclude_none=True)
                
            rules_list.append(main_corr_rule)
            
            return rules_list

        # 4. NẾU LÀ RULE BÌNH THƯỜNG (SINGLE-EVENT)
        detection.condition = getattr(correlation, "expression", None) or "1 of selection_*"
        metadata = SigmaMetadata(
            title=title,
            id=self._generate_rule_id(cve_id, title, tags),
            **metadata_base
        )
        return SigmaRule(
            metadata=metadata,
            logsource={"category": primary_logsource},
            detection=detection,
            x_family=family or "generic",
            x_signature=signature or family or "generic",
            x_detection_confidence=detection_confidence,
            x_correlation_required=bool(self._get(telemetry, "correlation_required")),
            x_correlation_logic=bool(self._get(telemetry, "correlation_required")) and getattr(correlation, "expression", "") != "1 of selection_*",
            x_correlation_reasoning=getattr(correlation, "reasoning", ""),
            x_secondary_logsources=secondary_logsources,
        )

    def save_rule(self, rules: list[SigmaRule] | SigmaRule) -> Path:
        if not isinstance(rules, list):
            rules = [rules]

        cve_id = self._extract_cve_from_references(rules[0].metadata.references) or "CVE-UNKNOWN"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / f"{cve_id}.yml"
        
        yaml_texts = []
        pending_corr = getattr(self, '_pending_correlation', None)
        
        for i, rule in enumerate(rules):
            rule_yaml = rule.to_yaml()
            
            # Nếu là rule cuối cùng và hệ thống có chứa luật tương quan (pending_corr)
            if i == len(rules) - 1 and pending_corr and len(rules) > 1:
                # Thêm action: correlation (chuẩn SigmaHQ)
                corr_lines = ["action: correlation", "correlation:"]
                for k, v in pending_corr.items():
                    if isinstance(v, list):
                        corr_lines.append(f"    {k}:")
                        for item in v:
                            corr_lines.append(f"        - {item}")
                    else:
                        corr_lines.append(f"    {k}: {v}")
                corr_str = "\n".join(corr_lines)
                
                # Cắt bỏ block dummy detection và thay bằng correlation block
                rule_yaml = re.sub(
                    r'detection:\s*\n(?:\s*(?:condition|selections):[^\n]*\n?)*', 
                    corr_str + '\n', 
                    rule_yaml
                )
                
                # Dùng Regex cạo sạch dòng logsource rỗng
                rule_yaml = re.sub(r'logsource:\s*(?:\{\})?\s*\n', '', rule_yaml)
                
                self._pending_correlation = None # Reset state
                
            yaml_texts.append(rule_yaml)

        # Ghi các rule ra file, cách nhau bằng "---" chuẩn YAML multi-document
        yaml_content = "\n---\n".join(yaml_texts)
        output_path.write_text(yaml_content, encoding="utf-8")
        return output_path

    def _generate_title(self, core: CoreCVEData, analysis: TechnicalAnalysis | dict[str, object] | None, family: str | None, signature: str | None) -> str:
        cve_id = self._get(core, "cve_id") or "CVE"
        title_family = self._display_family(signature or family, cve_id)
        outcome = self._display_outcome(self._get(analysis, "likely_outcome"))
        if title_family == "Exploitation" and outcome != "Exploitation":
            title_family = outcome
        if not title_family:
            title_family = outcome if outcome != "Exploitation" else cve_id
        if outcome and outcome not in title_family:
            return f"{title_family} {outcome} Attempt"
        return f"{title_family} Attempt"

    def _generate_description(
        self,
        core: CoreCVEData,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
    ) -> str:
        cve_id = self._get(core, "cve_id") or "CVE-UNKNOWN"
        family = self._display_family(self._normalize_slug(self._get(analysis, "signature")) or self._normalize_slug(self._get(analysis, "family")), cve_id)
        outcome = self._display_outcome(self._get(analysis, "likely_outcome")).lower()
        techniques = self._build_description_techniques(attack)

        lines = [
            "Detects exploitation activity associated with",
            f"{family} ({cve_id})",
            f"resulting in {outcome}.",
        ]
        if techniques:
            lines.extend([
                "",
                f"Mapped ATT&CK techniques include {', '.join(techniques)}.",
            ])
        else:
            lines.extend([
                "",
                "Mapped ATT&CK techniques include none.",
            ])
        return "\n".join(lines)

    def _build_tags(self, attack: AttackMapping | dict[str, object] | None) -> list[str]:
        techniques = self._list(self._get(attack, "techniques"))
        subtechniques = self._list(self._get(attack, "subtechniques"))
        tags = [self._attack_tag(technique) for technique in techniques]
        if not tags and subtechniques:
            tags = [self._attack_tag(item.split(".")[0]) for item in subtechniques]
        return self._unique(tags)

    def _build_description_techniques(self, attack: AttackMapping | dict[str, object] | None) -> list[str]:
        techniques = self._list(self._get(attack, "techniques"))
        subtechniques = self._list(self._get(attack, "subtechniques"))
        return self._unique(techniques + subtechniques)

    def _build_detection(self, behaviors: list[str], telemetry: TelemetryAssessment | dict[str, object] | None) -> dict[str, dict[str, list[str]]]:
        behavior_map: dict[str, tuple[str, str, str]] = {
            "web_request": ("selection_web", "cs-uri-query|contains", "${IOC}"),
            "process_creation": ("selection_process", "CommandLine|contains", "${PAYLOAD}"),
            "network_connection": ("selection_network", "DestinationHostname|contains", "${C2}"),
            "tool_download": ("selection_download", "CommandLine|contains", "${PAYLOAD}"),
            "public_facing_exploit": ("selection_exploit", "cs-uri-query|contains", "${IOC}"),
        }
        selections: dict[str, dict[str, list[str]]] = {}
        for behavior in behaviors:
            mapping = behavior_map.get(behavior)
            if not mapping:
                continue
            selection_name, field_name, placeholder = mapping
            selections[selection_name] = {field_name: [placeholder]}

        if selections:
            return selections

        primary_logsource, _ = self._select_logsources(telemetry)
        fallback_map = {
            "process_creation": {"selection_process": {"CommandLine|contains": ["${PAYLOAD}"]}},
            "webserver": {"selection_web": {"cs-uri-query|contains": ["${IOC}"]}},
            "network_connection": {"selection_network": {"DestinationHostname|contains": ["${C2}"]}},
        }
        return fallback_map.get(primary_logsource, {"selection_generic": {"EventID|contains": ["${IOC}"]}})

    def _select_logsources(self, telemetry: TelemetryAssessment | dict[str, object] | None) -> tuple[str, list[str]]:
        priority = ["process_creation", "webserver", "network_connection"]
        categories = self._list(self._get(telemetry, "candidate_logsources"))
        sigma_logsources = self._get(telemetry, "sigma_logsources") or []
        for item in sigma_logsources:
            category = self._get(item, "category")
            if category:
                categories.append(str(category))

        categories = self._unique([self._normalize_slug(item) or item for item in categories if item])
        for candidate in priority:
            if candidate in categories:
                secondary = [item for item in categories if item != candidate]
                return candidate, secondary
        if categories:
            return categories[0], categories[1:]
        return "process_creation", []

    def _build_related(self, coverage: CoverageAssessment | dict[str, object] | None) -> list[dict[str, str]]:
        related_ids = self._list(self._get(coverage, "related_rules"))
        if not related_ids:
            related_ids = self._list(self._get(coverage, "matched_rule_ids"))
        return [{"id": rule_id, "type": "similar"} for rule_id in self._unique(related_ids)]

    def _fill_detection_keywords(
        self,
        detection: SigmaDetection,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        core: CoreCVEData,
    ) -> None:
        # CHỈ lấy extracted_keywords từ analysis, tuyệt đối KHÔNG add cve_id vào đây
        keywords = self._unique(self._list(self._get(analysis, "extracted_keywords")))
        
        description = str(self._get(core, "description") or "").lower()
        family = self._normalize_slug(self._get(analysis, "family"))
        web_keyword_map = {
            "php": ".php",
            "jsp": ".jsp",
            "aspx": ".aspx",
            "python": ".py",
        }
        web_exts = [ext for key, ext in web_keyword_map.items() if key in description or key in keywords]
        if family == "file_upload" and not web_exts:
            web_exts = [".php", ".jsp", ".aspx", ".sh", ".py"]

        for selection in detection.selections.values():
            for field, values in list(selection.items()):
                if not isinstance(values, list):
                    continue
                
                # Sửa lỗi đắp payload: Nếu không có keyword thực tế, xóa placeholder
                # Sửa lỗi đắp payload: Nếu không có keyword thực tế, xóa placeholder hoặc gán fallback
                if any("${PAYLOAD}" in str(value) for value in values):
                    if keywords:
                        selection[field] = keywords
                    elif field == "CommandLine|contains": # THÊM DÒNG NÀY ĐỂ FALLBACK
                        selection[field] = ["cmd.exe", "/bin/sh", "powershell", "curl", "wget"]
                    else:
                        selection[field] = [] 
                
                # Xử lý riêng cho webshell/file_upload
                elif field == "TargetFilename|contains" and any("${IOC}" in str(value) for value in values):
                    if family == "file_upload" and web_exts:
                        selection[field] = web_exts # Bỏ việc cộng thêm cve_id vào đây
                    elif keywords:
                         selection[field] = keywords
                    else:
                        selection[field] = []

                # Fallback cho trường hợp CommandLine trống ngay từ đầu
                elif field == "CommandLine|contains" and not values:
                    selection[field] = keywords if keywords else ["cmd.exe", "/bin/sh", "powershell", "curl", "wget"]
                        
            # Dọn dẹp các field rỗng sau khi xóa placeholder
            for key in list(selection.keys()):
                if not selection[key]:
                    del selection[key]

    def _severity_to_level(self, cvss_score: float | None, severity: str | None) -> str:
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "critical"
            if cvss_score >= 7.0:
                return "high"
            if cvss_score >= 4.0:
                return "medium"
            return "low"
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
        }
        return severity_map.get((severity or "").lower(), "medium")

    def _coverage_to_status(self, decision: str | None) -> str:
        status_map = {
            "NEW": "experimental",
            "EXTEND": "test",
            "SIMILAR": "stable",
            "EXISTING": "stable",
            "OBSOLETE": "stable",
        }
        return status_map.get((decision or "").upper(), "experimental")

    def _generate_rule_id(self, cve_id: str, title: str, tags: list[str]) -> str:
        basis = f"{cve_id}:{title}:{','.join(tags)}"
        return str(uuid5(NAMESPACE_URL, basis))

    def _combine_confidence(self, analysis_confidence: float | None, telemetry_confidence: float | None) -> float | None:
        if analysis_confidence is None and telemetry_confidence is None:
            return None
        if analysis_confidence is None:
            return round(float(telemetry_confidence or 0.0), 2)
        if telemetry_confidence is None:
            return round(float(analysis_confidence), 2)
        return round((analysis_confidence + telemetry_confidence) / 2, 2)

    def _adjust_confidence(
        self,
        analysis_confidence: float | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
        family: str | None,
        signature: str | None,
        correlation_expression: str,
    ) -> float | None:
        if analysis_confidence is None:
            return None
        confidence = float(analysis_confidence)
        if self._get(telemetry, "correlation_required"):
            if correlation_expression != "1 of selection_*":
                confidence += 0.03
                normalized_family = self._normalize_slug(family)
                normalized_signature = self._normalize_slug(signature)
                if normalized_signature in FAMILY_CORRELATION_RULES or normalized_family in FAMILY_CORRELATION_RULES:
                    confidence += 0.02
        return round(min(confidence, 0.99), 2)

    def _display_family(self, value: str | None, cve_id: str) -> str:
        overrides = {
            "spring4shell": "Spring4Shell",
            "jndi_injection": "Log4Shell",
            "log4shell": "Log4Shell",
            "printnightmare": "PrintNightmare",
            "path_traversal": "Apache Path Traversal",
        }
        normalized = self._normalize_slug(value)
        if normalized in overrides:
            return overrides[normalized]
        if normalized:
            return " ".join(part.capitalize() for part in normalized.split("_"))
        if cve_id == "CVE-2021-44228":
            return "Log4Shell"
        if cve_id == "CVE-2022-22965":
            return "Spring4Shell"
        return "Exploitation"

    def _display_outcome(self, value: str | None) -> str:
        normalized = self._normalize_slug(value)
        overrides = {
            "remote_code_execution": "Remote Code Execution",
            "information_disclosure": "Information Disclosure",
            "privilege_escalation": "Privilege Escalation",
            "limited_impact": "Exploitation",
        }
        if normalized in overrides:
            return overrides[normalized]
        if normalized:
            return " ".join(part.capitalize() for part in normalized.split("_"))
        return "Exploitation"

    def _signature_from_reasoning(self, analysis: TechnicalAnalysis | dict[str, object] | None) -> str | None:
        reasons = self._list(self._get(analysis, "classification_reason"))
        for reason in reasons:
            if reason.startswith("signature:"):
                return reason.split(":", 1)[1].strip()
        return None

    def _attack_tag(self, technique: str) -> str:
        return f"attack.{technique.lower()}"

    def _extract_cve_from_references(self, references: Iterable[str]) -> str | None:
        for reference in references:
            if "/CVE-" in reference:
                return reference.rsplit("/", 1)[-1]
        return None

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

    def _float(self, value: object | None) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _normalize_slug(self, value: object | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower().replace(".", "_").replace("-", "_")
        return text or None

    def _unique(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result