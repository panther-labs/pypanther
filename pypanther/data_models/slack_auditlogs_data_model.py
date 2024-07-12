from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardSlackAuditLogs(PantherDataModel):
    id_: str = "Standard.Slack.AuditLogs"
    display_name: str = "Slack Audit Logs"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Slack_AuditLogs]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="$.actor.user.name"),
        PantherDataModelMapping(name="user_agent", path="$.context.ua"),
        PantherDataModelMapping(name="source_ip", path="$.context.ip_address"),
        PantherDataModelMapping(name="user", path="$.entity.user.name"),
    ]
