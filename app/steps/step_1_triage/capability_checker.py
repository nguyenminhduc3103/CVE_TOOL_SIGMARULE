from __future__ import annotations

from dataclasses import dataclass

from app.shared.models.core import CoreCVEData
from app.shared.models.triage import TriageContext


@dataclass(frozen=True)
class CapabilityClassification:
    value: str
    confidence_modifier: float
    telemetry_modifier: float
    reasoning: str


class CapabilityChecker:
    async def assess(self, core: CoreCVEData, triage: TriageContext) -> str:
        return self.classify(core).value

    def classify(self, core: CoreCVEData) -> CapabilityClassification:
        text = " ".join(
            part.lower()
            for part in [core.cve_id, core.description or "", " ".join(core.cwe_ids or [])]
        )

        if self._has_any(text, ("firmware", "uefi", "bios", "bootloader", "microcode", "embedded")):
            return CapabilityClassification("out_of_scope_firmware", 0.6, 0.6, "Firmware-only issue")
        if self._has_any(text, ("crypto", "cryptographic", "cipher", "encryption", "signature", "tls", "ssl")):
            return CapabilityClassification("out_of_scope_crypto", 0.6, 0.6, "Cryptographic weakness")
        if self._has_any(text, ("hardware", "side-channel", "cache timing", "spectre", "meltdown", "rowhammer")):
            return CapabilityClassification("out_of_scope_hardware", 0.65, 0.65, "Hardware or side-channel issue")
        if self._has_any(text, ("printer", "spooler", "driver", "printnightmare")):
            return CapabilityClassification("in_scope", 1.0, 1.0, "General software issue")
        return CapabilityClassification("in_scope", 1.0, 1.0, "General software issue")

    def _has_any(self, text: str, needles: tuple[str, ...]) -> bool:
        return any(needle in text for needle in needles)
