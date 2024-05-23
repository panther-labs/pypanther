from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_base_helpers import gsuite_details_lookup as details_lookup
from pypanther.log_types import LogType


def get_event_type(event):
    # currently, only tracking a few event types
    # Pattern match this event to the recon actions
    if deep_get(event, "id", "applicationName") == "admin":
        if bool(details_lookup("DELEGATED_ADMIN_SETTINGS", ["ASSIGN_ROLE"], event)):
            return event_type.ADMIN_ROLE_ASSIGNED
    if details_lookup("login", ["login_failure"], event):
        return event_type.FAILED_LOGIN
    if deep_get(event, "id", "applicationName") == "login":
        return event_type.SUCCESSFUL_LOGIN
    return None


class StandardGSuiteReports(PantherDataModel):
    DataModelID: str = "Standard.GSuite.Reports"
    DisplayName: str = "GSuite Reports"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.GSuite_Reports]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.actor.email"),
        PantherDataModelMapping(
            Name="assigned_admin_role",
            Path="$.events[*].parameters[?(@.name == 'ROLE_NAME')].value",
        ),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="ipAddress"),
        PantherDataModelMapping(
            Name="user", Path="$.events[*].parameters[?(@.name == 'USER_EMAIL')].value"
        ),
    ]
