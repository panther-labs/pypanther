from pypanther.base import DataModel, DataModelMapping, LogType


class StandardSlackAccessLogs(DataModel):
    id: str = "Standard.Slack.AccessLogs"
    display_name: str = "Slack Access Logs"
    enabled: bool = True
    log_types: list[str] = [LogType.SLACK_ACCESS_LOGS]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="ip"),
        DataModelMapping(name="user_agent", path="user_agent"),
        DataModelMapping(name="actor_user", path="username"),
    ]
