from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers.panther_base_helpers import deep_get


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Crowdstrike FDR end with a trailing period, such as google.com.
    domain = deep_get(event, "event", "DomainName", default=None)
    if domain:
        domain = domain.rstrip(".")
    return domain


def get_process_name(event):
    platform = event.get("event_platform")
    # Extract process name from path
    # Win = \Device\HarddiskVolume2\Windows\System32\winlogon.exe
    # Lin = /usr/bin/run-parts
    # Mac = /usr/libexec/xpcproxy
    image_fn = deep_get(event, "event", "ImageFileName")
    if not image_fn:
        return None  # Explicitly return None if the key DNE
    if platform == "Win":
        return image_fn.split("\\")[-1]
    return image_fn.split("/")[-1]


class StandardCrowdstrikeFDR(DataModel):
    id: str = "Standard.Crowdstrike.FDR"
    display_name: str = "Crowdstrike FDR"
    enabled: bool = True
    log_types: list[str] = [LogType.CROWDSTRIKE_FDR_EVENT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.event.UserName"),
        DataModelMapping(name="cmd", path="$.event.CommandLine"),
        DataModelMapping(name="destination_ip", path="$.event.RemoteAddressIP4"),
        DataModelMapping(name="destination_port", path="$.event.RemotePort"),
        DataModelMapping(name="dns_query", method=get_dns_query),
        DataModelMapping(name="process_name", method=get_process_name),
        DataModelMapping(name="source_ip", path="$.aip"),
        DataModelMapping(name="source_port", path="$.event.LocalPort"),
    ]
