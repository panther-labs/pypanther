from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSVPCFlow(PantherDataModel):
    DataModelID: str = "Standard.AWS.VPCFlow"
    DisplayName: str = "AWS VPCFlow"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.AWS_VPCFlow]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="destination_ip", Path="dstAddr"),
        PantherDataModelMapping(Name="destination_port", Path="dstPort"),
        PantherDataModelMapping(Name="source_ip", Path="srcAddr"),
        PantherDataModelMapping(Name="source_port", Path="srcPort"),
        PantherDataModelMapping(Name="user_agent", Path="userAgent"),
        PantherDataModelMapping(Name="log_status", Path="log-status"),
    ]
