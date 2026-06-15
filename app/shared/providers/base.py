"""Base provider interface."""
from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """Abstract base for CVE data providers (NVD, KEV, EPSS)."""
    name: str = "base"

    @abstractmethod
    async def enrich(self, cve_id: str) -> Any:
        pass

    @abstractmethod
    async def fetch(self, cve_id: str) -> Any:
        pass
