"""EVTX Parser — decode dữ liệu nhị phân .evtx trong bộ nhớ RAM và lọc theo Event ID.

Target Event IDs:
- Event ID 1 (Sysmon Process Creation) / 4688 (Windows Process Creation)
- Event ID 3 (Sysmon Network Connection)
- Event ID 11 (Sysmon File Create)
- Event ID 13 (Sysmon Registry Value Set)
"""
from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from typing import Any

from config.logging import get_logger

logger = get_logger(__name__)

TARGET_EVENT_IDS = {1, 3, 11, 13, 4688}


class EVTXMemoryParser:
    """Decoder tệp nhị phân .evtx trực tiếp trong bộ nhớ RAM."""

    def parse_evtx_bytes(self, evtx_bytes: bytes, max_records: int = 20) -> list[dict[str, Any]]:
        """
        Decode dữ liệu nhị phân EVTX trong RAM và lọc theo Event ID trọng tâm.

        Args:
            evtx_bytes: Luồng byte nhị phân của tệp .evtx.
            max_records: Số lượng bản ghi tối đa giữ lại.

        Returns:
            Danh sách các dict chứa dữ liệu event đã chuẩn hóa.
        """
        if not evtx_bytes:
            return []

        parsed_events: list[dict[str, Any]] = []

        try:
            # Thử import Evtx parser chuyên dụng
            from Evtx.Evtx import Evtx
            from Evtx.Views import evtx_file_xml_view

            with Evtx(io.BytesIO(evtx_bytes)) as evtx:
                for xml_str, _ in evtx_file_xml_view(evtx.get_header()):
                    event = self._parse_xml_event(xml_str)
                    if event and event.get("event_id") in TARGET_EVENT_IDS:
                        parsed_events.append(event)
                        if len(parsed_events) >= max_records:
                            break

        except ImportError:
            logger.info("[EVTX Parser] python-evtx library not installed, fallback to XML regex heuristic")
            parsed_events = self._regex_fallback_parse(evtx_bytes, max_records)
        except Exception as exc:
            logger.warning("[EVTX Parser] Error decoding EVTX bytes", error=str(exc))
            parsed_events = self._regex_fallback_parse(evtx_bytes, max_records)

        logger.info("[EVTX Parser] Extracted events", count=len(parsed_events))
        return parsed_events

    def _parse_xml_event(self, xml_str: str) -> dict[str, Any] | None:
        """Parse XML string của 1 Windows Event Record."""
        try:
            # Clean namespace for easier parsing
            clean_xml = re.sub(r' xmlns="[^"]+"', '', xml_str)
            root = ET.fromstring(clean_xml)

            system = root.find("System")
            if system is None:
                return None

            event_id_elem = system.find("EventID")
            if event_id_elem is None or not event_id_elem.text:
                return None

            event_id = int(event_id_elem.text)
            channel = system.findtext("Channel") or ""
            computer = system.findtext("Computer") or ""
            time_created = ""
            time_elem = system.find("TimeCreated")
            if time_elem is not None:
                time_created = time_elem.get("SystemTime", "")

            # EventData parsing
            event_data_dict: dict[str, str] = {}
            event_data = root.find("EventData")
            if event_data is not None:
                for data in event_data.findall("Data"):
                    name = data.get("Name")
                    if name and data.text:
                        event_data_dict[name] = data.text

            return {
                "event_id": event_id,
                "channel": channel,
                "computer": computer,
                "time_created": time_created,
                "image": event_data_dict.get("Image") or event_data_dict.get("NewProcessName"),
                "command_line": event_data_dict.get("CommandLine"),
                "parent_image": event_data_dict.get("ParentImage"),
                "event_data": event_data_dict
            }
        except Exception:
            return None

    def _regex_fallback_parse(self, evtx_bytes: bytes, max_records: int) -> list[dict[str, Any]]:
        """Fallback heuristic regex parser cho chuỗi ascii/utf-16 trong evtx bytes."""
        events: list[dict[str, Any]] = []
        try:
            # Extract printable ascii strings from binary bytes
            text = evtx_bytes.decode("ascii", errors="ignore")
            matches = re.findall(r"(EventID|CommandLine|Image|ParentImage)[\s:=]+([^\r\n\x00]+)", text)
            
            data_map: dict[str, str] = {}
            for key, val in matches:
                data_map[key] = val.strip()

            if data_map:
                events.append({
                    "event_id": 1,
                    "channel": "Heuristic/Fallback",
                    "image": data_map.get("Image"),
                    "command_line": data_map.get("CommandLine"),
                    "parent_image": data_map.get("ParentImage"),
                    "event_data": data_map
                })
        except Exception:
            pass
        return events
