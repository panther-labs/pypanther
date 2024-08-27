from pypanther.base import DataModel, DataModelMapping, LogType


class StandardAWSVPCFlow(DataModel):
    id: str = "Standard.AWS.VPCFlow"
    display_name: str = "AWS VPCFlow"
    enabled: bool = True
    log_types: list[str] = [LogType.AWS_VPC_FLOW]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="destination_ip", path="dstAddr"),
        DataModelMapping(name="destination_port", path="dstPort"),
        DataModelMapping(name="source_ip", path="srcAddr"),
        DataModelMapping(name="source_port", path="srcPort"),
        DataModelMapping(name="user_agent", path="userAgent"),
        DataModelMapping(name="log_status", path="log-status"),
    ]
