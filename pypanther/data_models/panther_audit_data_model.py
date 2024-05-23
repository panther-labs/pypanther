from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

audit_log_type_map = {
    "CREATE_USER": event_type.USER_ACCOUNT_CREATED,
    "DELETE_USER": event_type.USER_ACCOUNT_DELETED,
    "UPDATE_USER": event_type.USER_ACCOUNT_MODIFIED,
    "CREATE_USER_ROLE": event_type.USER_GROUP_CREATED,
    "DELETE_USER_ROLE": event_type.USER_GROUP_DELETED,
    "UPDATE_USER_ROLE": event_type.USER_ROLE_MODIFIED,
}


def get_event_type(event):
    audit_log_type = event.get("actionName")
    matched = audit_log_type_map.get(audit_log_type)
    if matched is not None:
        return matched
    return None


def get_actor_user(event):
    # First prefer actor.attributes.email
    #  automatons like SCIM won't have an actor.attributes.email
    actor_user = deep_get(event, "actor", "attributes", "email")
    if actor_user is None:
        actor_user = deep_get(event, "actor", "id")
    return actor_user


class StandardPantherAudit(PantherDataModel):
    DataModelID: str = "Standard.Panther.Audit"
    DisplayName: str = "Panther Audit Logs"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Panther_Audit]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="sourceIP"),
        PantherDataModelMapping(Name="user_agent", Path="userAgent"),
        PantherDataModelMapping(Name="actor_user", Method=get_actor_user),
        PantherDataModelMapping(Name="user", Path="$.actionParams.input.email"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
    ]
