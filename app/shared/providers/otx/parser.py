from __future__ import annotations

from typing import Any
from app.core.logging import get_logger


class OTXParser:
    """Parser xử lý phản hồi từ AlienVault OTX để trích xuất danh sách Threat Actors."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def extract_threat_actors(self, raw: Any) -> list[str]:
        """Trích xuất và làm sạch danh sách nhóm tấn công (Adversaries) từ dữ liệu OTX thô.

        Duyệt qua danh sách các pulses liên quan đến CVE, lấy thông tin trường 'adversary'
        và loại bỏ các giá trị chung chung (như 'threat', 'unknown', v.v.).
        """
        self.logger.info("[OTX] Đang trích xuất nhóm tấn công (Threat Actors) từ dữ liệu OTX")
        if not isinstance(raw, dict):
            return []

        pulse_info = raw.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        if not pulses:
            self.logger.info("[OTX] Không tìm thấy pulse nào liên quan để trích xuất threat actors.")
            return []

        actors: set[str] = set()
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            adversary = pulse.get("adversary")
            if not adversary:
                continue

            # Một số pulse có thể chứa nhiều tác nhân đe dọa phân tách bằng dấu phẩy/chấm phẩy
            adversary_str = str(adversary).strip()
            for delimiter in [",", ";"]:
                if delimiter in adversary_str:
                    parts = adversary_str.split(delimiter)
                    break
            else:
                parts = [adversary_str]

            for part in parts:
                cleaned = part.strip()
                if not cleaned:
                    continue
                
                # Bỏ qua các từ khóa rác hoặc chung chung không phải tên nhóm tấn công cụ thể
                cleaned_lower = cleaned.lower()
                
                # Từ khóa chỉ mã độc, công cụ
                malware_keywords = {
                    "rat", "malware", "trojan", "backdoor", "botnet", "miner", "stealer", 
                    "worm", "ransomware", "spyware", "keylogger", "rootkit", "adware",
                    "webshell", "agent", "ransom"
                }
                
                # Từ khóa chỉ kỹ thuật khai thác, khái niệm chung
                technique_keywords = {
                    "exploit", "exploitation", "vulnerability", "injection", "scan", 
                    "scanning", "scanner", "bypass", "payload", "poc", "proof of concept",
                    "threat", "adversary", "campaign", "actor", "threat actor", "threat actors",
                    "null", "none", "unknown"
                }
                
                words = cleaned_lower.replace("-", " ").replace("_", " ").replace(".", " ").split()
                is_valid = True
                for word in words:
                    if word in malware_keywords or word in technique_keywords:
                        is_valid = False
                        break
                        
                if is_valid:
                    actors.add(cleaned)

        results = sorted(list(actors))
        self.logger.info("[OTX] Đã trích xuất thành công nhóm tấn công", count=len(results), actors=results)
        return results
