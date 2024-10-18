from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type
from pypanther.helpers.base import deep_get
from pypanther.helpers.gsuite import gsuite_details_lookup as details_lookup


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


class StandardGSuiteReports(DataModel):
    id: str = "Standard.GSuite.Reports"
    display_name: str = "GSuite Reports"
    enabled: bool = True
    log_types: list[str] = [LogType.GSUITE_REPORTS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.actor.email"),
        DataModelMapping(name="assigned_admin_role", path="$.events[*].parameters[?(@.name == 'ROLE_NAME')].value"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="ipAddress"),
        DataModelMapping(name="user", path="$.events[*].parameters[?(@.name == 'USER_EMAIL')].value"),
    ]
