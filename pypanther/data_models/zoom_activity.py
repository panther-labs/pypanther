import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping, LogType


def get_event_type(event):
    if event.get("type") == "Sign in":
        return event_type.SUCCESSFUL_LOGIN
    if event.get("type") == "Sign out":
        return event_type.SUCCESSFUL_LOGOUT
    return None


class StandardZoomActivity(DataModel):
    id: str = "Standard.Zoom.Activity"
    display_name: str = "Zoom Activity"
    enabled: bool = True
    log_types: list[str] = [LogType.ZOOM_ACTIVITY]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="email"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="ip_address"),
    ]
