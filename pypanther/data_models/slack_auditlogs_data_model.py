from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


class StandardSlackAuditLogs(PantherDataModel):
    DataModelID: str = "Standard.Slack.AuditLogs"
    DisplayName: str = "Slack Audit Logs"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Slack_AuditLogs]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.actor.user.name"),
        PantherDataModelMapping(Name="user_agent", Path="$.context.ua"),
        PantherDataModelMapping(Name="source_ip", Path="$.context.ip_address"),
        PantherDataModelMapping(Name="user", Path="$.entity.user.name"),
    ]
