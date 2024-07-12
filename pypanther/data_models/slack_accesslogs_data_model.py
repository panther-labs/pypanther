from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardSlackAccessLogs(PantherDataModel):
    id_: str = "Standard.Slack.AccessLogs"
    display_name: str = "Slack Access Logs"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Slack_AccessLogs]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="source_ip", path="ip"),
        PantherDataModelMapping(name="user_agent", path="user_agent"),
        PantherDataModelMapping(name="actor_user", path="username"),
    ]
