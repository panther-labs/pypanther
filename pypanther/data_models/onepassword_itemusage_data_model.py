from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType

# 1Password item usage logs don't have event types, this file is a placeholder. All events are
# the viewing or usage of an item in 1Password


class StandardOnePasswordItemUsage(PantherDataModel):
    id_: str = "Standard.OnePassword.ItemUsage"
    display_name: str = "1Password Item Usage Events"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.OnePassword_ItemUsage]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.user.email"),
        PantherDataModelMapping(name="source_ip", path="$.client.ipaddress"),
    ]
