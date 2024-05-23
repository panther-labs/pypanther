import ipaddress
from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType


def get_event_type(event):
    # currently, only tracking a few event types
    if (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "IAMUser"
    ):
        if deep_get(event, "responseElements", "ConsoleLogin") == "Failure":
            return event_type.FAILED_LOGIN
        if deep_get(event, "responseElements", "ConsoleLogin") == "Success":
            return event_type.SUCCESSFUL_LOGIN
    if event.get("eventName") == "CreateUser":
        return event_type.USER_ACCOUNT_CREATED
    if event.get("eventName") == "CreateAccountResult":
        return event_type.ACCOUNT_CREATED
    return None


def load_ip_address(event):
    """
    CloudTrail occasionally sets non-IPs in the sourceIPAddress field.
    This method ensures that either an IPv4 or IPv6 address is always returned.
    """
    source_ip = event.get("sourceIPAddress")
    if not source_ip:
        return None
    try:
        ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(source_ip)
        except ipaddress.AddressValueError:
            return None
    return source_ip


class StandardAWSCloudTrail(PantherDataModel):
    DataModelID: str = "Standard.AWS.CloudTrail"
    DisplayName: str = "AWS CloudTrail"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.AWS_CloudTrail]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.userIdentity..userName"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Method=load_ip_address),
        PantherDataModelMapping(Name="user_agent", Path="userAgent"),
        PantherDataModelMapping(Name="user", Path="$.responseElements.user.userName"),
        PantherDataModelMapping(Name="user_account_id", Path="$.responseElements.user.userId"),
    ]
