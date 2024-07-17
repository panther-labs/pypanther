from pypanther.base import DataModel, DataModelMapping, LogType


class StandardAWSS3ServerAccess(DataModel):
    id: str = "Standard.AWS.S3ServerAccess"
    display_name: str = "AWS S3 Server Access"
    enabled: bool = True
    log_types: list[str] = [LogType.AWS_S3_SERVER_ACCESS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="http_status", path="httpstatus"),
        DataModelMapping(name="source_ip", path="remoteip"),
        DataModelMapping(name="user_agent", path="useragent"),
    ]
