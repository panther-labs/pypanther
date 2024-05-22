from typing import List

from panther_analysis.base import PantherDataModel, PantherDataModelMapping


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Cisco Umbrella end with a trailing period, such as google.com.
    domain = event.get("domain")
    if domain:
        domain = domain.rstrip(".")
    return domain


class StandardCiscoUmbrellaDNS(PantherDataModel):
    DataModelID: str = "Standard.CiscoUmbrella.DNS"
    DisplayName: str = "Cisco Umbrella DNS"
    Enabled: bool = True
    LogTypes: List[str] = ["CiscoUmbrella.DNS"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="internalIp"),
        PantherDataModelMapping(Name="source_port", Path="srcPort"),
        PantherDataModelMapping(Name="dns_query", Method=get_dns_query),
    ]
