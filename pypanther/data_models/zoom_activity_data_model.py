from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


def get_event_type(event):
    if event.get("type") == "Sign in":
        return event_type.SUCCESSFUL_LOGIN
    if event.get("type") == "Sign out":
        return event_type.SUCCESSFUL_LOGOUT
    return None


class StandardZoomActivity(PantherDataModel):
    id_: str = "Standard.Zoom.Activity"
    display_name: str = "Zoom Activity"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Zoom_Activity]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="email"),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="ip_address"),
    ]
