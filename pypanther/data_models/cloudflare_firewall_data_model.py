from pypanther.base import DataModel, DataModelMapping, LogType


class StandardCloudflareFirewall(DataModel):
    id_: str = "Standard.Cloudflare.Firewall"
    display_name: str = "Cloudflare Firewall"
    enabled: bool = True
    log_types: list[str] = [LogType.Cloudflare_Firewall]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="ClientIP"),
        DataModelMapping(name="user_agent", path="ClientRequestUserAgent"),
        DataModelMapping(name="http_status", path="EdgeResponseStatus"),
    ]
