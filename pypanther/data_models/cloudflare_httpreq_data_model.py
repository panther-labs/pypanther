from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardCloudflareHttpReq(DataModel):
    id_: str = "Standard.Cloudflare.HttpReq"
    display_name: str = "Cloudflare Firewall"
    enabled: bool = True
    log_types: List[str] = [LogType.Cloudflare_HttpRequest]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="ClientIP"),
        DataModelMapping(name="user_agent", path="ClientRequestUserAgent"),
        DataModelMapping(name="http_status", path="EdgeResponseStatus"),
        DataModelMapping(name="source_port", path="ClientSrcPort"),
    ]
