from __future__ import annotations

from app.sigma_generator.family_detection.base import DetectionTemplate
from app.sigma_generator.family_detection.templates import (
    ApachePathTraversalTemplate,
    GenericRCETemplate,
    Log4ShellTemplate,
    PrintNightmareTemplate,
    Spring4ShellTemplate,
    StrutsOgnlTemplate,
)


class DetectionTemplateRegistry:
    def __init__(self) -> None:
        self._templates: list[DetectionTemplate] = []
        self._generic_template: DetectionTemplate = GenericRCETemplate()
        self.register(Log4ShellTemplate())
        self.register(Spring4ShellTemplate())
        self.register(PrintNightmareTemplate())
        self.register(StrutsOgnlTemplate())
        self.register(ApachePathTraversalTemplate())
        self.register(self._generic_template)

    def register(self, template: DetectionTemplate) -> DetectionTemplate:
        self._templates.append(template)
        return template

    def resolve(self, family: str | None, signature: str | None) -> DetectionTemplate:
        normalized_family = self._normalize(family)
        normalized_signature = self._normalize(signature)

        if normalized_signature:
            for template in self._non_generic_templates():
                if template.supports(None, normalized_signature):
                    return template

        if normalized_family:
            for template in self._non_generic_templates():
                if template.supports(normalized_family, None):
                    return template

        return self._generic_template

    def _non_generic_templates(self) -> list[DetectionTemplate]:
        return [template for template in self._templates if template is not self._generic_template]

    def _normalize(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower().replace(".", "_").replace("-", "_")
        return text or None