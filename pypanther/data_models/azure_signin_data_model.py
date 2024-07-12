from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_azuresignin_helpers import actor_user, is_sign_in_event
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import PantherLogType


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
    id_: str = "Standard.Azure.Audit.SignIn"
    display_name: str = "Azure SignIn Logs DataModel"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Azure_Audit]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", method=get_actor_user),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="$.properties.ipAddress"),
    ]
