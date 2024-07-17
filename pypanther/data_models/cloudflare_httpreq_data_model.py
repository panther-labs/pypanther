from pypanther.base import DataModel, DataModelMapping, LogType


class StandardCloudflareHttpReq(DataModel):
    id: str = "Standard.Cloudflare.HttpReq"
    display_name: str = "Cloudflare Firewall"
    enabled: bool = True
    log_types: list[str] = [LogType.CLOUDFLARE_HTTP_REQUEST]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="ClientIP"),
        DataModelMapping(name="user_agent", path="ClientRequestUserAgent"),
        DataModelMapping(name="http_status", path="EdgeResponseStatus"),
        DataModelMapping(name="source_port", path="ClientSrcPort"),
    ]
