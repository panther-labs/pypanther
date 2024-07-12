from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSVPCDns(PantherDataModel):
    id_: str = "Standard.AWS.VPCDns"
    display_name: str = "AWS VPC DNS"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.AWS_VPCDns]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="srcAddr"),
        PantherDataModelMapping(name="source_port", path="srcPort"),
        PantherDataModelMapping(name="dns_query", path="query_name"),
    ]
