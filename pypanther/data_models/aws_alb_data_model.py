from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping


class StandardAWSALB(PantherDataModel):
    DataModelID: str = "Standard.AWS.ALB"
    DisplayName: str = "AWS Application Load Balancer"
    Enabled: bool = True
    LogTypes: List[str] = ["AWS.ALB"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="destination_ip", Path="targetIp"),
        PantherDataModelMapping(Name="source_ip", Path="clientIp"),
        PantherDataModelMapping(Name="user_agent", Path="userAgent"),
    ]
