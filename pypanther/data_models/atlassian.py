from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type
from pypanther.helpers.base import deep_get

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


class StandardAtlassianAudit(DataModel):
    id: str = "Standard.Atlassian.Audit"
    display_name: str = "Atlassian Audit Logs"
    enabled: bool = True
    log_types: list[str] = [LogType.ATLASSIAN_AUDIT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.EventActor.Name"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="$.EventLocation.IP"),
    ]
