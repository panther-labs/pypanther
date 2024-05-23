from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION, zendesk_get_roles
from pypanther.log_types import LogType

ZENDESK_TWO_FACTOR_SOURCES = {
    "Two-Factor authentication for all admins and agents",
    "Require Two Factor",
}


def get_event_type(event):
    # user related events
    if event.get("source_type", "") == "user":
        return get_user_event_type(event)
    # account related events
    if event.get("source_type", "") == "account_setting":
        return get_account_setting_event_type(event)
    return None


def get_user_event_type(event):
    # check for login events
    if event.get("action") == "login":
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("successful sign-in"):
            return event_type.SUCCESSFUL_LOGIN
    # check for admin assignment
    if event.get("action") == "update":
        _, new_role = zendesk_get_roles(event)
        if new_role and is_admin_role(new_role):
            return event_type.ADMIN_ROLE_ASSIGNED
    return None


def get_account_setting_event_type(event):
    if event.get("source_label", "") in ZENDESK_TWO_FACTOR_SOURCES:
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
            return event_type.MFA_DISABLED
    return None


def is_admin_role(new_role):
    if new_role and isinstance(new_role, str):
        for admin in ("admin", "account owner"):
            if admin in new_role.lower():
                return True
    return False


def get_assigned_admin_role(event):
    _, new_role = zendesk_get_roles(event)
    if is_admin_role(new_role):
        return new_role
    return None


def get_user(event):
    # some events will have the user in the source_label field,
    # otherwise the user field may not be relevant
    if event.get("source_type", "").lower() == "user":
        return event.get("source_label")
    return "<UNKNOWN_USER>"


class StandardZendeskAuditLog(PantherDataModel):
    DataModelID: str = "Standard.Zendesk.AuditLog"
    DisplayName: str = "Zendesk Audit"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Zendesk_Audit]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="actor_name"),
        PantherDataModelMapping(Name="assigned_admin_role", Method=get_assigned_admin_role),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="ip_address"),
        PantherDataModelMapping(Name="user", Method=get_user),
    ]
