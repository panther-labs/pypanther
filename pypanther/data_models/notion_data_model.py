from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType


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


class StandardNotionAuditLogs(PantherDataModel):
    DataModelID: str = "Standard.Notion.AuditLogs"
    DisplayName: str = "Notion Audit Logs"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Notion_AuditLogs]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Method=get_actor_user),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="$.event.ip_address"),
    ]
