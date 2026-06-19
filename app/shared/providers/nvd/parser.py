from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.constants import MAX_CPES_PREVIEW, MAX_REFERENCES_PREVIEW
from app.core.logging import get_logger
from app.shared.models.core import CoreCVEData


class NVDParser:
    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.last_truncation: dict[str, bool] = {
            "references_truncated": False,
            "cpes_truncated": False,
        }

    def normalize(self, raw: Any) -> CoreCVEData:
        """Normalize raw NVD payload into CoreCVEData.

        TODO boundaries:
        - no HTTP logic here
        - no business scoring logic here
        - keep parsing deterministic and resilient to missing fields
        """
        self.logger.info("[NVD] Parsing CVE data")
        cve = self._extract_cve(raw)

        description = self._extract_description(cve)
        cvss_score, cvss_vector, severity = self._extract_cvss(cve)
        cwe_ids = self._extract_cwes(cve)
        references = self._extract_references(cve)
        cpes = self._extract_cpes(cve)
        published_at = self._parse_datetime(cve.get("published"))
        modified_at = self._parse_datetime(cve.get("lastModified"))

        self.last_truncation = {
            "references_truncated": self._has_more_references(cve, references),
            "cpes_truncated": self._has_more_cpes(cve, cpes),
        }

        affected_products = []
        if cpes:
            try:
                from app.shared.parsers.cpe_parser import parse_cpe_list
                parsed_cpes = parse_cpe_list(cpes)
                seen = set()
                for item in parsed_cpes:
                    part = item.get("part", "")
                    vendor = item.get("vendor", "")
                    product = item.get("product", "")
                    version = item.get("version", "")
                    update = item.get("update", "")

                    # Tiền tố theo phân loại thiết bị
                    prefix = ""
                    if part == "o":
                        prefix = "[OS] "
                    elif part == "h":
                        prefix = "[HW] "
                    elif part == "a":
                        prefix = "[APP] "

                    formatted_vendor = vendor.capitalize()
                    formatted_prod = product.replace("_", " ").title()
                    prod_label = f"{prefix}{formatted_vendor} {formatted_prod}"
                    if version and version != "*" and version != "-":
                        prod_label += f" {version}"
                    if update and update != "*" and update != "-":
                        prod_label += f" {update}"

                    if prod_label not in seen:
                        seen.add(prod_label)
                        affected_products.append(prod_label)
            except Exception as e:
                self.logger.warning("[NVD] Failed to parse affected products from CPEs", error=str(e))

        parsed = CoreCVEData(
            cve_id=str(cve.get("id") or raw.get("cve_id") or ""),
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            cwe_ids=cwe_ids or None,
            references=references or None,
            cpes=cpes or None,
            affected_products=affected_products or None,
            published_at=published_at,
            modified_at=modified_at,
        )
        self.logger.info(
            "[NVD] Parsed CVSS",
            cve_id=parsed.cve_id,
            cvss_score=parsed.cvss_score,
            severity=parsed.severity,
        )
        return parsed

    def _extract_cve(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {}
        vulnerabilities = raw.get("vulnerabilities") or []
        if not vulnerabilities:
            return raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
        first_item = vulnerabilities[0] or {}
        return first_item.get("cve") if isinstance(first_item.get("cve"), dict) else first_item

    def _extract_description(self, cve: dict[str, Any]) -> str:
        for entry in cve.get("descriptions") or []:
            if entry.get("lang") == "en" and entry.get("value"):
                return str(entry["value"])
        for entry in cve.get("descriptions") or []:
            if entry.get("value"):
                return str(entry["value"])
        return ""

    def _extract_cvss(self, cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
        metrics = cve.get("metrics") or {}
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key) or []
            if not entries:
                continue
            metric = entries[0] or {}
            cvss_data = metric.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            return self._to_float(score), self._to_str(vector), self._to_str(severity)
        return None, None, None

    def _extract_cwes(self, cve: dict[str, Any]) -> list[str]:
        cwes: list[str] = []
        for weakness in cve.get("weaknesses") or []:
            for description in weakness.get("description") or []:
                value = description.get("value")
                if value and value not in cwes:
                    cwes.append(str(value))
        return cwes

    def _extract_references(self, cve: dict[str, Any]) -> list[str]:
        refs: list[str] = []
        for reference in cve.get("references") or []:
            url = reference.get("url")
            if url and url not in refs:
                refs.append(str(url))
            if len(refs) >= MAX_REFERENCES_PREVIEW:
                break
        return refs

    def _extract_cpes(self, cve: dict[str, Any]) -> list[str]:
        cpes: list[str] = []
        configurations = cve.get("configurations") or []
        for configuration in configurations:
            for node in configuration.get("nodes") or []:
                for cpe_match in node.get("cpeMatch") or []:
                    criteria = cpe_match.get("criteria")
                    if criteria and criteria not in cpes:
                        cpes.append(str(criteria))
                    if len(cpes) >= MAX_CPES_PREVIEW:
                        break
                if len(cpes) >= MAX_CPES_PREVIEW:
                    break
            if len(cpes) >= MAX_CPES_PREVIEW:
                break
        return cpes

    def _has_more_references(self, cve: dict[str, Any], references: list[str]) -> bool:
        raw_references = cve.get("references") or []
        if len(references) < MAX_REFERENCES_PREVIEW:
            return len(raw_references) > len(references)
        return len(raw_references) > MAX_REFERENCES_PREVIEW

    def _has_more_cpes(self, cve: dict[str, Any], cpes: list[str]) -> bool:
        raw_count = 0
        configurations = cve.get("configurations") or []
        for configuration in configurations:
            for node in configuration.get("nodes") or []:
                raw_count += len(node.get("cpeMatch") or [])
        if len(cpes) < MAX_CPES_PREVIEW:
            return raw_count > len(cpes)
        return raw_count > MAX_CPES_PREVIEW

    def _parse_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        text = str(value).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    def _to_float(self, value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _to_str(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None
