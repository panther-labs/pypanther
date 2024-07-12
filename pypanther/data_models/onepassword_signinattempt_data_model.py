from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


def get_event_type(event):
    failed_login_events = ["credentials_failed", "mfa_failed", "modern_version_failed"]

    if event.get("category") == "success":
        return event_type.SUCCESSFUL_LOGIN

    if event.get("category") in failed_login_events:
        return event_type.FAILED_LOGIN

    return None


class StandardOnePasswordSignInAttempt(PantherDataModel):
    id_: str = "Standard.OnePassword.SignInAttempt"
    display_name: str = "1Password Signin Events"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.OnePassword_SignInAttempt]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.target_user.email"),
        PantherDataModelMapping(name="source_ip", path="$.client.ip_address"),
        PantherDataModelMapping(name="event_type", method=get_event_type),
    ]
