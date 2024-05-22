from typing import List

import panther_analysis.helpers.panther_event_type_helpers as event_type
from panther_analysis.base import PantherDataModel, PantherDataModelMapping


def get_event_type(event):
    if event.get("type") == "Sign in":
        return event_type.SUCCESSFUL_LOGIN
    if event.get("type") == "Sign out":
        return event_type.SUCCESSFUL_LOGOUT
    return None


class StandardZoomActivity(PantherDataModel):
    DataModelID: str = "Standard.Zoom.Activity"
    DisplayName: str = "Zoom Activity"
    Enabled: bool = True
    LogTypes: List[str] = ["Zoom.Activity"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="email"),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="ip_address"),
    ]
