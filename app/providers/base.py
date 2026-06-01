from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """Abstract base for providers. Providers should ONLY fetch raw data."""

    @abstractmethod
    async def fetch(self, identifier: str) -> Any:
        raise NotImplementedError()
