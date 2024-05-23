from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


class StandardCloudflareFirewall(PantherDataModel):
    DataModelID: str = "Standard.Cloudflare.Firewall"
    DisplayName: str = "Cloudflare Firewall"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Cloudflare_Firewall]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="ClientIP"),
        PantherDataModelMapping(Name="user_agent", Path="ClientRequestUserAgent"),
        PantherDataModelMapping(Name="http_status", Path="EdgeResponseStatus"),
    ]
