from pypanther.base import DataModel, DataModelMapping, LogType


class StandardAWSVPCDns(DataModel):
    id_: str = "Standard.AWS.VPCDns"
    display_name: str = "AWS VPC DNS"
    enabled: bool = True
    log_types: list[str] = [LogType.AWS_VPCDns]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="srcAddr"),
        DataModelMapping(name="source_port", path="srcPort"),
        DataModelMapping(name="dns_query", path="query_name"),
    ]
