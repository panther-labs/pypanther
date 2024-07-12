from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSVPCFlow(PantherDataModel):
    id_: str = "Standard.AWS.VPCFlow"
    display_name: str = "AWS VPCFlow"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.AWS_VPCFlow]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="destination_ip", path="dstAddr"),
        PantherDataModelMapping(name="destination_port", path="dstPort"),
        PantherDataModelMapping(name="source_ip", path="srcAddr"),
        PantherDataModelMapping(name="source_port", path="srcPort"),
        PantherDataModelMapping(name="user_agent", path="userAgent"),
        PantherDataModelMapping(name="log_status", path="log-status"),
    ]
