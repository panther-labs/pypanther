from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping


class StandardAWSS3ServerAccess(PantherDataModel):
    DataModelID: str = "Standard.AWS.S3ServerAccess"
    DisplayName: str = "AWS S3 Server Access"
    Enabled: bool = True
    LogTypes: List[str] = ["AWS.S3ServerAccess"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="http_status", Path="httpstatus"),
        PantherDataModelMapping(Name="source_ip", Path="remoteip"),
        PantherDataModelMapping(Name="user_agent", Path="useragent"),
    ]
