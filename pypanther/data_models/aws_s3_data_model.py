from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardAWSS3ServerAccess(DataModel):
    id_: str = "Standard.AWS.S3ServerAccess"
    display_name: str = "AWS S3 Server Access"
    enabled: bool = True
    log_types: List[str] = [LogType.AWS_S3ServerAccess]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="http_status", path="httpstatus"),
        DataModelMapping(name="source_ip", path="remoteip"),
        DataModelMapping(name="user_agent", path="useragent"),
    ]
