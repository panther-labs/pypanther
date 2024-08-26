from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type
from pypanther.helpers.azuresignin import actor_user, is_sign_in_event
from pypanther.helpers.base import deep_get


def get_event_type(event):
    if not is_sign_in_event(event):
        return None

    error_code = deep_get(event, "properties", "status", "errorCode", default=0)
    if error_code == 0:
        return event_type.SUCCESSFUL_LOGIN
    return event_type.FAILED_LOGIN


def get_actor_user(event):
    return actor_user(event)


class StandardAzureAuditSignIn(DataModel):
    id: str = "Standard.Azure.Audit.SignIn"
    display_name: str = "Azure SignIn Logs DataModel"
    enabled: bool = True
    log_types: list[str] = [LogType.AZURE_AUDIT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", method=get_actor_user),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="$.properties.ipAddress"),
    ]
