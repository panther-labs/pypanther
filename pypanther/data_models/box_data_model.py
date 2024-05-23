from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get("event_type") == "FAILED_LOGIN":
        return event_type.FAILED_LOGIN
    if event.get("event_type") == "LOGIN":
        return event_type.SUCCESSFUL_LOGIN
    return None


class StandardBoxEvent(PantherDataModel):
    DataModelID: str = "Standard.Box.Event"
    DisplayName: str = "Box Events"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Box_Event]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.created_by.name"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="ip_address"),
    ]
