from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


def get_event_type(event):
    if event.get("type") == "Sign in":
        return event_type.SUCCESSFUL_LOGIN
    if event.get("type") == "Sign out":
        return event_type.SUCCESSFUL_LOGOUT
    return None


class StandardZoomActivity(DataModel):
    id_: str = "Standard.Zoom.Activity"
    display_name: str = "Zoom Activity"
    enabled: bool = True
    log_types: List[str] = [LogType.Zoom_Activity]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="email"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="ip_address"),
    ]
