from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSALB(PantherDataModel):
    DataModelID: str = "Standard.AWS.ALB"
    DisplayName: str = "AWS Application Load Balancer"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.AWS_ALB]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="destination_ip", Path="targetIp"),
        PantherDataModelMapping(Name="source_ip", Path="clientIp"),
        PantherDataModelMapping(Name="user_agent", Path="userAgent"),
    ]
