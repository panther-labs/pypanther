from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType


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
    DataModelID: str = "Standard.Crowdstrike.FDR"
    DisplayName: str = "Crowdstrike FDR"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Crowdstrike_FDREvent]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.event.UserName"),
        PantherDataModelMapping(Name="cmd", Path="$.event.CommandLine"),
        PantherDataModelMapping(Name="destination_ip", Path="$.event.RemoteAddressIP4"),
        PantherDataModelMapping(Name="destination_port", Path="$.event.RemotePort"),
        PantherDataModelMapping(Name="dns_query", Method=get_dns_query),
        PantherDataModelMapping(Name="process_name", Method=get_process_name),
        PantherDataModelMapping(Name="source_ip", Path="$.aip"),
        PantherDataModelMapping(Name="source_port", Path="$.event.LocalPort"),
    ]
