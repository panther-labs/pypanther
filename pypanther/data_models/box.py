import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping, LogType


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get("event_type") == "FAILED_LOGIN":
        return event_type.FAILED_LOGIN
    if event.get("event_type") == "LOGIN":
        return event_type.SUCCESSFUL_LOGIN
    return None


class StandardBoxEvent(DataModel):
    id: str = "Standard.Box.Event"
    display_name: str = "Box Events"
    enabled: bool = True
    log_types: list[str] = [LogType.BOX_EVENT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.created_by.name"),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="ip_address"),
    ]
