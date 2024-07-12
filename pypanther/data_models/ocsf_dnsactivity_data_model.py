from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardOCSFDnsActivity(PantherDataModel):
    id_: str = "Standard.OCSF.DnsActivity"
    display_name: str = "OCSF DNS Activity"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.OCSF_DnsActivity]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="$.src_endpoint.ip"),
        PantherDataModelMapping(name="source_port", path="$.src_endpoint.port"),
        PantherDataModelMapping(name="dns_query", path="$.query.hostname"),
    ]
