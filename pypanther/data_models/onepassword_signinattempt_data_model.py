import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping, LogType


def get_event_type(event):
    failed_login_events = ["credentials_failed", "mfa_failed", "modern_version_failed"]

    if event.get("category") == "success":
        return event_type.SUCCESSFUL_LOGIN

    if event.get("category") in failed_login_events:
        return event_type.FAILED_LOGIN

    return None


class StandardOnePasswordSignInAttempt(DataModel):
    id: str = "Standard.OnePassword.SignInAttempt"
    display_name: str = "1Password Signin Events"
    enabled: bool = True
    log_types: list[str] = [LogType.ONEPASSWORD_SIGNIN_ATTEMPT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.target_user.email"),
        DataModelMapping(name="source_ip", path="$.client.ip_address"),
        DataModelMapping(name="event_type", method=get_event_type),
    ]
