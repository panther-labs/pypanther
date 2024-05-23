from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


def get_event_type(event):
    # pylint: disable=too-many-return-statements
    # pylint: disable=too-many-branches
    # pylint: disable=too-complex
    if event.get("category_type") == "User":
        if event.get("action") == "Add":
            return event_type.USER_ACCOUNT_CREATED
        if event.get("action") == "Delete":
            return event_type.USER_ACCOUNT_DELETED
        if event.get("action") == "Update" and "to Admin" in event.get("operation_detail"):
            return event_type.ADMIN_ROLE_ASSIGNED
        if event.get("action") == "Update":
            return event_type.USER_ACCOUNT_MODIFIED

    if event.get("category_type") == "User Group":
        if event.get("action") == "Add":
            return event_type.USER_GROUP_CREATED
        if event.get("action") == "Update":
            return event_type.USER_GROUP_MODIFIED
        if event.get("action") == "Delete":
            return event_type.USER_GROUP_DELETED

    if event.get("category_type") == "Role":
        if event.get("action") == "Add":
            return event_type.USER_ROLE_CREATED
        if event.get("action") == "Update":
            return event_type.USER_ROLE_MODIFIED
        if event.get("action") == "Delete":
            return event_type.USER_ROLE_DELETED
    return None


class StandardZoomOperation(PantherDataModel):
    DataModelID: str = "Standard.Zoom.Operation"
    DisplayName: str = None
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Zoom_Operation]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="operator"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
    ]
