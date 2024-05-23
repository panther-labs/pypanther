from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


class StandardAWSVPCDns(PantherDataModel):
    DataModelID: str = "Standard.AWS.VPCDns"
    DisplayName: str = "AWS VPC DNS"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.AWS_VPCDns]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="srcAddr"),
        PantherDataModelMapping(Name="source_port", Path="srcPort"),
        PantherDataModelMapping(Name="dns_query", Path="query_name"),
    ]
