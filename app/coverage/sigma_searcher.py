from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    tags: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    logsource_category: str | None
    logsource_product: str | None
    logsource_service: str | None
    status: str | None
    detection: str
    source_path: str | None = None
    title_tokens: tuple[str, ...] = ()
    behavior_markers: tuple[str, ...] = ()


class RuleInventory(ABC):
    @abstractmethod
    def list_rules(self) -> list[SigmaRule]:
        raise NotImplementedError


class InMemoryRuleInventory(RuleInventory):
    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self._rules = list(rules or [])

    def list_rules(self) -> list[SigmaRule]:
        return list(self._rules)


class FilesystemRuleInventory(RuleInventory):
    def __init__(self, rules_root: str | Path | None = None) -> None:
        self.rules_root = Path(rules_root) if rules_root else Path.cwd() / "rules"

    def list_rules(self) -> list[SigmaRule]:
        if not self.rules_root.exists():
            return []

        parsed: list[SigmaRule] = []
        for path in self.rules_root.rglob("*.yml"):
            parsed.extend(self._parse_rule_file(path))
        return parsed

    def _parse_rule_file(self, path: Path) -> list[SigmaRule]:
        content = path.read_text(encoding="utf-8", errors="ignore")
        documents = [chunk for chunk in re.split(r"^---\s*$", content, flags=re.MULTILINE) if chunk.strip()]
        rules: list[SigmaRule] = []
        for doc in documents:
            rule_id = self._extract_scalar(doc, "id") or path.stem
            title = self._extract_scalar(doc, "title") or path.stem
            tags = tuple(self._extract_list_block(doc, "tags"))
            category = self._extract_logsource_value(doc, "category")
            product = self._extract_logsource_value(doc, "product")
            service = self._extract_logsource_value(doc, "service")
            status = self._extract_scalar(doc, "status")
            detection = self._extract_block(doc, "detection")

            techniques = tuple(
                sorted(
                    {
                        tag.lower().replace("attack.", "").upper()
                        for tag in tags
                        if tag.lower().startswith("attack.t")
                    }
                )
            )
            title_tokens = tuple(self._tokenize_title(title))
            behavior_markers = tuple(self._derive_behavior_markers(title, tags, detection))

            if not (rule_id or title):
                continue

            rules.append(
                SigmaRule(
                    rule_id=rule_id,
                    title=title,
                    tags=tags,
                    attack_techniques=techniques,
                    logsource_category=category,
                    logsource_product=product,
                    logsource_service=service,
                    status=status,
                    detection=detection,
                    source_path=str(path),
                    title_tokens=title_tokens,
                    behavior_markers=behavior_markers,
                )
            )
        return rules

    def _tokenize_title(self, title: str) -> list[str]:
        return [token for token in re.findall(r"[a-z0-9]+", title.lower()) if token]

    def _derive_behavior_markers(self, title: str, tags: tuple[str, ...], detection: str) -> list[str]:
        corpus = " ".join([title.lower(), " ".join(tag.lower() for tag in tags), detection.lower()])
        mapping = {
            "process_creation": ("process", "cmd", "powershell", "commandline", "t1059"),
            "network_connection": ("network", "callback", "http", "ldap", "rmi", "t1071", "t1046"),
            "web_request": ("web", "request", "uri", "query", "t1190", "ognl", "jndi"),
            "file_read": ("read", "disclosure", "traversal", "../"),
            "file_write": ("write", "drop", "upload", "shell"),
            "registry_modification": ("registry", "hive"),
            "image_load": ("image", "dll", "module"),
            "privilege_escalation": ("privilege", "elevation", "spooler", "spoolsv", "t1068"),
            "public_facing_exploit": ("cve", "exploit", "public", "internet", "facing"),
        }

        markers: list[str] = []
        for behavior, keys in mapping.items():
            if any(key in corpus for key in keys):
                markers.append(behavior)
        return markers

    def _extract_scalar(self, text: str, key: str) -> str | None:
        match = re.search(rf"^{key}:\s*(.+)$", text, flags=re.MULTILINE)
        if not match:
            return None
        return match.group(1).strip().strip('"\'')

    def _extract_block(self, text: str, key: str) -> str:
        match = re.search(rf"^{key}:\s*$", text, flags=re.MULTILINE)
        if not match:
            return ""
        start = match.end()
        lines: list[str] = []
        for line in text[start:].splitlines():
            if line and not line.startswith(" ") and not line.startswith("\t"):
                break
            lines.append(line)
        return "\n".join(lines)

    def _extract_list_block(self, text: str, key: str) -> list[str]:
        block = self._extract_block(text, key)
        if block:
            return [line.strip().lstrip("-").strip().strip('"\'') for line in block.splitlines() if line.strip().startswith("-")]

        inline = re.search(rf"^{key}:\s*\[(.+?)\]\s*$", text, flags=re.MULTILINE)
        if not inline:
            return []
        return [item.strip().strip('"\'') for item in inline.group(1).split(",") if item.strip()]

    def _extract_logsource_value(self, text: str, logsource_key: str) -> str | None:
        block = self._extract_block(text, "logsource")
        if not block:
            return None
        match = re.search(rf"^\s*{logsource_key}:\s*(.+)$", block, flags=re.MULTILINE)
        if not match:
            return None
        return match.group(1).strip().strip('"\'')


class SigmaRepositoryIndexer:
    def __init__(self, inventory: RuleInventory) -> None:
        self.inventory = inventory

    def load(self) -> list[SigmaRule]:
        return self.inventory.list_rules()


# Backward-compatible aliases
SigmaRuleRepository = RuleInventory
InMemorySigmaRuleRepository = InMemoryRuleInventory
FilesystemSigmaRuleRepository = FilesystemRuleInventory
