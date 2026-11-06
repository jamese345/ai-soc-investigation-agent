import unittest

from src.tools.ioc_lookup import IOCLookup


class TestOTXIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lookup = IOCLookup()

    def test_real_otx_lookup(self):
        result = self.lookup.lookup("8.8.8.8")

        self.assertEqual(result.ioc, "8.8.8.8")
        self.assertEqual(result.ioc_type, "IPv4")
        self.assertIn("AlienVault OTX", result.sources)


if __name__ == "__main__":
    unittest.main()