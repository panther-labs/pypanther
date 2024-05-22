from typing import List
from panther_analysis.base import PantherDataModel, PantherDataModelMapping


class StandardSlackAuditLogs(PantherDataModel):
    DataModelID: str = "Standard.Slack.AuditLogs"
    DisplayName: str = "Slack Audit Logs"
    Enabled: bool = True
    LogTypes: List[str] = ["Slack.AuditLogs"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="$.actor.user.name"),
        PantherDataModelMapping(Name="user_agent", Path="$.context.ua"),
        PantherDataModelMapping(Name="source_ip", Path="$.context.ip_address"),
        PantherDataModelMapping(Name="user", Path="$.entity.user.name"),
    ]
