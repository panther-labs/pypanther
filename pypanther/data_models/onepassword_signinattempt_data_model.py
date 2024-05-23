from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


def get_event_type(event):
    failed_login_events = ["credentials_failed", "mfa_failed", "modern_version_failed"]

    if event.get("category") == "success":
        return event_type.SUCCESSFUL_LOGIN

    if event.get("category") in failed_login_events:
        return event_type.FAILED_LOGIN

    return None


class StandardOnePasswordSignInAttempt(PantherDataModel):
    DataModelID: str = "Standard.OnePassword.SignInAttempt"
    DisplayName: str = "1Password Signin Events"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.OnePassword_SignInAttempt]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.target_user.email"),
        PantherDataModelMapping(Name="source_ip", Path="$.client.ip_address"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
    ]
