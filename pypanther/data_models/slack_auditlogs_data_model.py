from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardSlackAuditLogs(DataModel):
    id_: str = "Standard.Slack.AuditLogs"
    display_name: str = "Slack Audit Logs"
    enabled: bool = True
    log_types: List[str] = [LogType.Slack_AuditLogs]
    mappings: List[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.actor.user.name"),
        DataModelMapping(name="user_agent", path="$.context.ua"),
        DataModelMapping(name="source_ip", path="$.context.ip_address"),
        DataModelMapping(name="user", path="$.entity.user.name"),
    ]
