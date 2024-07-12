from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardSlackAccessLogs(DataModel):
    id_: str = "Standard.Slack.AccessLogs"
    display_name: str = "Slack Access Logs"
    enabled: bool = True
    log_types: List[str] = [LogType.Slack_AccessLogs]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="ip"),
        DataModelMapping(name="user_agent", path="user_agent"),
        DataModelMapping(name="actor_user", path="username"),
    ]
