from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_azuresignin_helpers import actor_user, is_sign_in_event
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType


def get_event_type(event):
    if not is_sign_in_event(event):
        return None

    error_code = deep_get(event, "properties", "status", "errorCode", default=0)
    if error_code == 0:
        return event_type.SUCCESSFUL_LOGIN
    return event_type.FAILED_LOGIN


def get_actor_user(event):
    return actor_user(event)


class StandardAzureAuditSignIn(PantherDataModel):
    DataModelID: str = "Standard.Azure.Audit.SignIn"
    DisplayName: str = "Azure SignIn Logs DataModel"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Azure_Audit]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Method=get_actor_user),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="$.properties.ipAddress"),
    ]
