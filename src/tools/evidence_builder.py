from src.models.schemas import Evidence, IOCResult


def ioc_result_to_evidence(result: IOCResult) -> Evidence:
    description = (
        f"IOC {result.ioc} was classified as {result.reputation} "
        f"with {result.risk.value} risk based on "
        f"AlienVault OTX intelligence."
    )

    relevance = (
        f"The IOC presents {result.risk.value} risk and should be "
        f"considered during the investigation."
    )

    return Evidence(
        source="AlienVault OTX",
        description=f"{description} {relevance}",
        relevance=result.risk.value,
        confidence=result.confidence,
    )