import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping, LogType


def get_event_type(event):
    # currently, only tracking a handful of event types
    if event.get("event_type_id") == 72 and event.get("privilege_name") == "Super user":
        return event_type.ADMIN_ROLE_ASSIGNED
    if event.get("event_type_id") == 6:
        return event_type.FAILED_LOGIN
    if event.get("event_type_id") == 5:
        return event_type.SUCCESSFUL_LOGIN
    if event.get("event_type_id") == 13:
        return event_type.USER_ACCOUNT_CREATED
    return None


class StandardOneLoginEvents(DataModel):
    id: str = "Standard.OneLogin.Events"
    display_name: str = "OneLogin Events"
    enabled: bool = True
    log_types: list[str] = [LogType.ONELOGIN_EVENTS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="actor_user_name"),
        DataModelMapping(name="assigned_admin_role", path="privilege_name"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="ipaddr"),
        DataModelMapping(name="user", path="user_name"),
        DataModelMapping(name="user_account_id", path="user_id"),
        DataModelMapping(name="user_agent", path="user_agent"),
    ]
