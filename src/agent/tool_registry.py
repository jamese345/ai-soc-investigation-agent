from src.tools.ioc_tool import IOCTool
from src.tools.log_search import LogSearchTool
from src.tools.mitre_tool import MITRETool


def build_tool_registry():
    """Build the investigation agent's available tools."""

    return {
        "IOC_LOOKUP": IOCTool(),
        "LOG_SEARCH": LogSearchTool(),
        "MITRE_LOOKUP": MITRETool(),
    }