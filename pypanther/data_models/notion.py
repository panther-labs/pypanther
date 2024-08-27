from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type
from pypanther.helpers.base import deep_get


def get_event_type(event):
    # pylint: disable=too-many-return-statements
    etype = deep_get(event, "event", "type")
    return {
        "user.login": event_type.SUCCESSFUL_LOGIN,
        "user.logout": event_type.SUCCESSFUL_LOGOUT,
        "user.settings.email_updated": event_type.USER_ACCOUNT_MODIFIED,
        "user.settings.login_method.mfa_backup_code_updated": event_type.MFA_RESET,
        "user.settings.login_method.mfa_totp_updated": event_type.MFA_RESET,
        "user.settings.login_method.password_added": event_type.USER_ACCOUNT_MODIFIED,
        "user.settings.preferred_name_updated": event_type.USER_ACCOUNT_MODIFIED,
        "user.settings.profile_photo_updated": event_type.USER_ACCOUNT_MODIFIED,
        "workspace.permissions.member_role_updated": event_type.USER_ROLE_MODIFIED,
    }.get(etype, etype)


def get_actor_user(event):
    actor = deep_get(event, "event", "actor", "id", default="UNKNOWN USER")
    if deep_get(event, "event", "actor", "person"):
        actor = deep_get(event, "event", "actor", "person", "email", default="UNKNOWN USER")
    return actor


class StandardNotionAuditLogs(DataModel):
    id: str = "Standard.Notion.AuditLogs"
    display_name: str = "Notion Audit Logs"
    enabled: bool = True
    log_types: list[str] = [LogType.NOTION_AUDIT_LOGS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", method=get_actor_user),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="$.event.ip_address"),
    ]
