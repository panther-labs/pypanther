from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Cisco Umbrella end with a trailing period, such as google.com.
    domain = event.get("domain")
    if domain:
        domain = domain.rstrip(".")
    return domain


class StandardCiscoUmbrellaDNS(DataModel):
    id_: str = "Standard.CiscoUmbrella.DNS"
    display_name: str = "Cisco Umbrella DNS"
    enabled: bool = True
    log_types: List[str] = [LogType.CiscoUmbrella_DNS]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="internalIp"),
        DataModelMapping(name="source_port", path="srcPort"),
        DataModelMapping(name="dns_query", method=get_dns_query),
    ]
