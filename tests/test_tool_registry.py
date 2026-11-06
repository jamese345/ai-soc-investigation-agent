import unittest

from src.agent.tool_registry import build_tool_registry
from src.tools.ioc_tool import IOCTool
from src.tools.log_search import LogSearchTool
from src.tools.mitre_tool import MITRETool


class TestToolRegistry(unittest.TestCase):

    def test_registry_contains_all_tools(self):
        registry = build_tool_registry()

        self.assertIn("IOC_LOOKUP", registry)
        self.assertIn("LOG_SEARCH", registry)
        self.assertIn("MITRE_LOOKUP", registry)

    def test_ioc_tool_registered(self):
        registry = build_tool_registry()

        self.assertIsInstance(
            registry["IOC_LOOKUP"],
            IOCTool,
        )

    def test_log_tool_registered(self):
        registry = build_tool_registry()

        self.assertIsInstance(
            registry["LOG_SEARCH"],
            LogSearchTool,
        )

    def test_mitre_tool_registered(self):
        registry = build_tool_registry()

        self.assertIsInstance(
            registry["MITRE_LOOKUP"],
            MITRETool,
        )


if __name__ == "__main__":
    unittest.main()