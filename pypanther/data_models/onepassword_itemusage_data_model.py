from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType

# 1Password item usage logs don't have event types, this file is a placeholder. All events are
# the viewing or usage of an item in 1Password


class StandardOnePasswordItemUsage(PantherDataModel):
    DataModelID: str = "Standard.OnePassword.ItemUsage"
    DisplayName: str = "1Password Item Usage Events"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.OnePassword_ItemUsage]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.user.email"),
        PantherDataModelMapping(Name="source_ip", Path="$.client.ipaddress"),
    ]
