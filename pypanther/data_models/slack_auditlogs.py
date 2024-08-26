from pypanther.base import DataModel, DataModelMapping, LogType


class StandardSlackAuditLogs(DataModel):
    id: str = "Standard.Slack.AuditLogs"
    display_name: str = "Slack Audit Logs"
    enabled: bool = True
    log_types: list[str] = [LogType.SLACK_AUDIT_LOGS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.actor.user.name"),
        DataModelMapping(name="user_agent", path="$.context.ua"),
        DataModelMapping(name="source_ip", path="$.context.ip_address"),
        DataModelMapping(name="user", path="$.entity.user.name"),
    ]
