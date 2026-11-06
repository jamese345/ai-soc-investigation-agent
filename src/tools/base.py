from abc import ABC, abstractmethod
from typing import Any


class InvestigationTool(ABC):
    """Base interface for tools used by the AI SOC Investigation Agent."""

    name: str
    description: str

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """Execute the investigation tool."""
        raise NotImplementedError