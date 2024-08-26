import ipaddress

from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type
from pypanther.helpers.base import deep_get


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get("eventName") == "ConsoleLogin" and deep_get(event, "userIdentity", "type") == "IAMUser":
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


class StandardAWSCloudTrail(DataModel):
    id: str = "Standard.AWS.CloudTrail"
    display_name: str = "AWS CloudTrail"
    enabled: bool = True
    log_types: list[str] = [LogType.AWS_CLOUDTRAIL]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.userIdentity..userName"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", method=load_ip_address),
        DataModelMapping(name="user_agent", path="userAgent"),
        DataModelMapping(name="user", path="$.responseElements.user.userName"),
        DataModelMapping(name="user_account_id", path="$.responseElements.user.userId"),
    ]
