from typing import List

from panther_analysis.base import PantherDataModel, PantherDataModelMapping

# 1Password item usage logs don't have event types, this file is a placeholder. All events are
# the viewing or usage of an item in 1Password


class StandardOnePasswordItemUsage(PantherDataModel):
    DataModelID: str = "Standard.OnePassword.ItemUsage"
    DisplayName: str = "1Password Item Usage Events"
    Enabled: bool = True
    LogTypes: List[str] = ["OnePassword.ItemUsage"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.user.email"),
        PantherDataModelMapping(Name="source_ip", Path="$.client.ipaddress"),
    ]
