from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardOCSFDnsActivity(DataModel):
    id_: str = "Standard.OCSF.DnsActivity"
    display_name: str = "OCSF DNS Activity"
    enabled: bool = True
    log_types: List[str] = [LogType.OCSF_DnsActivity]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="$.src_endpoint.ip"),
        DataModelMapping(name="source_port", path="$.src_endpoint.port"),
        DataModelMapping(name="dns_query", path="$.query.hostname"),
    ]
