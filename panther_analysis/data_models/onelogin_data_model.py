from typing import List

import panther_analysis.helpers.panther_event_type_helpers as event_type
from panther_analysis.base import PantherDataModel, PantherDataModelMapping


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


class StandardOneLoginEvents(PantherDataModel):
    DataModelID: str = "Standard.OneLogin.Events"
    DisplayName: str = "OneLogin Events"
    Enabled: bool = True
    LogTypes: List[str] = ["OneLogin.Events"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="actor_user_name"),
        PantherDataModelMapping(Name="assigned_admin_role", Path="privilege_name"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="ipaddr"),
        PantherDataModelMapping(Name="user", Path="user_name"),
        PantherDataModelMapping(Name="user_account_id", Path="user_id"),
        PantherDataModelMapping(Name="user_agent", Path="user_agent"),
    ]
