from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardAWSALB(DataModel):
    id_: str = "Standard.AWS.ALB"
    display_name: str = "AWS Application Load Balancer"
    enabled: bool = True
    log_types: List[str] = [LogType.AWS_ALB]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="destination_ip", path="targetIp"),
        DataModelMapping(name="source_ip", path="clientIp"),
        DataModelMapping(name="user_agent", path="userAgent"),
    ]
