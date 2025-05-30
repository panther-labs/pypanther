from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers import event_type


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


class StandardZoomOperation(DataModel):
    id: str = "Standard.Zoom.Operation"
    display_name: str = None
    enabled: bool = True
    log_types: list[str] = [LogType.ZOOM_OPERATION]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="operator"),
        DataModelMapping(name="event_type", method=get_event_type),
    ]
