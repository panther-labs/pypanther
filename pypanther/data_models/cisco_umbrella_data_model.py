from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Cisco Umbrella end with a trailing period, such as google.com.
    domain = event.get("domain")
    if domain:
        domain = domain.rstrip(".")
    return domain


class StandardCiscoUmbrellaDNS(PantherDataModel):
    id_: str = "Standard.CiscoUmbrella.DNS"
    display_name: str = "Cisco Umbrella DNS"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.CiscoUmbrella_DNS]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="internalIp"),
        PantherDataModelMapping(name="source_port", path="srcPort"),
        PantherDataModelMapping(name="dns_query", method=get_dns_query),
    ]
