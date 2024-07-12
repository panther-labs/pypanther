from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSALB(PantherDataModel):
    id_: str = "Standard.AWS.ALB"
    display_name: str = "AWS Application Load Balancer"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.AWS_ALB]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="destination_ip", path="targetIp"),
        PantherDataModelMapping(name="source_ip", path="clientIp"),
        PantherDataModelMapping(name="user_agent", path="userAgent"),
    ]
