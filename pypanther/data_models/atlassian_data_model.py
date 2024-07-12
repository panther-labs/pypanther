from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import PantherLogType

audit_log_type_map = {
    "user_login": event_type.SUCCESSFUL_LOGIN,
    "user_logout": event_type.SUCCESSFUL_LOGOUT,
    "user_created": event_type.USER_ACCOUNT_CREATED,
    "twosv_disabled_for_user": event_type.MFA_DISABLED,
    "group_created": event_type.USER_GROUP_CREATED,
    "group_deleted": event_type.USER_GROUP_DELETED,
    "user_granted_role": event_type.USER_ROLE_MODIFIED,
    "user_revoked_role": event_type.USER_ROLE_DELETED,
}


def get_event_type(event):
    audit_log_type = deep_get(event, "AuditLog", "Type")
    matched = audit_log_type_map.get(audit_log_type)
    if matched is not None:
        return matched

    if audit_log_type in ("added_org_admin", "group_granted_admin_access"):
        return event_type.ADMIN_ROLE_ASSIGNED

    return None


class StandardAtlassianAudit(PantherDataModel):
    id_: str = "Standard.Atlassian.Audit"
    display_name: str = "Atlassian Audit Logs"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Atlassian_Audit]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.EventActor.Name"),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="$.EventLocation.IP"),
    ]
