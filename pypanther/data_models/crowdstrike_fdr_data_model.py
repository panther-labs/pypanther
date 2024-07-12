from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import PantherLogType


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


class StandardCrowdstrikeFDR(PantherDataModel):
    id_: str = "Standard.Crowdstrike.FDR"
    display_name: str = "Crowdstrike FDR"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Crowdstrike_FDREvent]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.event.UserName"),
        PantherDataModelMapping(name="cmd", path="$.event.CommandLine"),
        PantherDataModelMapping(name="destination_ip", path="$.event.RemoteAddressIP4"),
        PantherDataModelMapping(name="destination_port", path="$.event.RemotePort"),
        PantherDataModelMapping(name="dns_query", method=get_dns_query),
        PantherDataModelMapping(name="process_name", method=get_process_name),
        PantherDataModelMapping(name="source_ip", path="$.aip"),
        PantherDataModelMapping(name="source_port", path="$.event.LocalPort"),
    ]
