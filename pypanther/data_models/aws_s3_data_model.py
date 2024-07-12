from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAWSS3ServerAccess(PantherDataModel):
    id_: str = "Standard.AWS.S3ServerAccess"
    display_name: str = "AWS S3 Server Access"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.AWS_S3ServerAccess]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="http_status", path="httpstatus"),
        PantherDataModelMapping(name="source_ip", path="remoteip"),
        PantherDataModelMapping(name="user_agent", path="useragent"),
    ]
