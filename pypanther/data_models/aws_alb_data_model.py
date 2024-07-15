from pypanther.base import DataModel, DataModelMapping, LogType


class StandardAWSALB(DataModel):
    id: str = "Standard.AWS.ALB"
    display_name: str = "AWS Application Load Balancer"
    enabled: bool = True
    log_types: list[str] = [LogType.AWS_ALB]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="destination_ip", path="targetIp"),
        DataModelMapping(name="source_ip", path="clientIp"),
        DataModelMapping(name="user_agent", path="userAgent"),
    ]
