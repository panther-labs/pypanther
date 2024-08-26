from pypanther.base import DataModel, DataModelMapping, LogType

# 1Password item usage logs don't have event types, this file is a placeholder. All events are
# the viewing or usage of an item in 1Password


class StandardOnePasswordItemUsage(DataModel):
    id: str = "Standard.OnePassword.ItemUsage"
    display_name: str = "1Password Item Usage Events"
    enabled: bool = True
    log_types: list[str] = [LogType.ONEPASSWORD_ITEM_USAGE]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.user.email"),
        DataModelMapping(name="source_ip", path="$.client.ipaddress"),
    ]
