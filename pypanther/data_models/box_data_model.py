from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get("event_type") == "FAILED_LOGIN":
        return event_type.FAILED_LOGIN
    if event.get("event_type") == "LOGIN":
        return event_type.SUCCESSFUL_LOGIN
    return None


class StandardBoxEvent(PantherDataModel):
    id_: str = "Standard.Box.Event"
    display_name: str = "Box Events"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Box_Event]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.created_by.name"),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="ip_address"),
    ]
