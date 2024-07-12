from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_base_helpers import gsuite_details_lookup as details_lookup
from pypanther.log_types import PantherLogType


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
    id_: str = "Standard.GSuite.Reports"
    display_name: str = "GSuite Reports"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.GSuite_Reports]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.actor.email"),
        PantherDataModelMapping(
            name="assigned_admin_role",
            path="$.events[*].parameters[?(@.name == 'ROLE_NAME')].value",
        ),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="ipAddress"),
        PantherDataModelMapping(
            name="user", path="$.events[*].parameters[?(@.name == 'USER_EMAIL')].value"
        ),
    ]
