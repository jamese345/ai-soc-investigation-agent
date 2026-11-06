from src.tools.base import InvestigationTool
from src.tools.ioc_lookup import IOCLookup
from src.tools.evidence_builder import ioc_result_to_evidence


class IOCTool(InvestigationTool):
    """Investigation tool for enriching IOCs with threat intelligence."""

    name = "ioc_lookup"

    description = (
        "Looks up an IP address, domain, email, or URI using "
        "AlienVault OTX and converts the result into investigation evidence."
    )

    def __init__(self, lookup_client=None):
        self.lookup_client = lookup_client or IOCLookup()

    def execute(self, ioc: str):
        result = self.lookup_client.lookup(ioc)
        evidence = ioc_result_to_evidence(result)

        return {
            "ioc_result": result,
            "evidence": evidence,
        }