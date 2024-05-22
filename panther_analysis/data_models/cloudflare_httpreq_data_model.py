from typing import List
from panther_analysis.base import PantherDataModel, PantherDataModelMapping


class StandardCloudflareHttpReq(PantherDataModel):
    DataModelID: str = "Standard.Cloudflare.HttpReq"
    DisplayName: str = "Cloudflare Firewall"
    Enabled: bool = True
    LogTypes: List[str] = ["Cloudflare.HttpRequest"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="ClientIP"),
        PantherDataModelMapping(Name="user_agent", Path="ClientRequestUserAgent"),
        PantherDataModelMapping(Name="http_status", Path="EdgeResponseStatus"),
        PantherDataModelMapping(Name="source_port", Path="ClientSrcPort"),
    ]
