from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping


class StandardCloudflareFirewall(PantherDataModel):
    DataModelID: str = "Standard.Cloudflare.Firewall"
    DisplayName: str = "Cloudflare Firewall"
    Enabled: bool = True
    LogTypes: List[str] = ["Cloudflare.Firewall"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="ClientIP"),
        PantherDataModelMapping(Name="user_agent", Path="ClientRequestUserAgent"),
        PantherDataModelMapping(Name="http_status", Path="EdgeResponseStatus"),
    ]
