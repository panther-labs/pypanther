from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardSlackAccessLogs(PantherDataModel):
    DataModelID: str = "Standard.Slack.AccessLogs"
    DisplayName: str = "Slack Access Logs"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.Slack_AccessLogs]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="source_ip", Path="ip"),
        PantherDataModelMapping(Name="user_agent", Path="user_agent"),
        PantherDataModelMapping(Name="actor_user", Path="username"),
    ]
