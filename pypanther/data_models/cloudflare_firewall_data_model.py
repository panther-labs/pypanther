from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardCloudflareFirewall(PantherDataModel):
    id_: str = "Standard.Cloudflare.Firewall"
    display_name: str = "Cloudflare Firewall"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Cloudflare_Firewall]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="ClientIP"),
        PantherDataModelMapping(name="user_agent", path="ClientRequestUserAgent"),
        PantherDataModelMapping(name="http_status", path="EdgeResponseStatus"),
    ]
