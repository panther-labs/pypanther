from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardOCSFDnsActivity(PantherDataModel):
    DataModelID: str = "Standard.OCSF.DnsActivity"
    DisplayName: str = "OCSF DNS Activity"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.OCSF_DnsActivity]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="$.src_endpoint.ip"),
        PantherDataModelMapping(Name="source_port", Path="$.src_endpoint.port"),
        PantherDataModelMapping(Name="dns_query", Path="$.query.hostname"),
    ]
