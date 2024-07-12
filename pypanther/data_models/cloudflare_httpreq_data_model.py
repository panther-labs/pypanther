from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardCloudflareHttpReq(PantherDataModel):
    id_: str = "Standard.Cloudflare.HttpReq"
    display_name: str = "Cloudflare Firewall"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Cloudflare_HttpRequest]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="ClientIP"),
        PantherDataModelMapping(name="user_agent", path="ClientRequestUserAgent"),
        PantherDataModelMapping(name="http_status", path="EdgeResponseStatus"),
        PantherDataModelMapping(name="source_port", path="ClientSrcPort"),
    ]
