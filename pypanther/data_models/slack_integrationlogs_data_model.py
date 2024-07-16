from pypanther.base import DataModel, DataModelMapping, LogType


class StandardSlackIntegrationLogs(DataModel):
    id: str = "Standard.Slack.IntegrationLogs"
    display_name: str = "Slack Integration Logs"
    enabled: bool = True
    log_types: list[str] = [LogType.Slack_IntegrationLogs]
    mappings: list[DataModelMapping] = [DataModelMapping(name="actor_user", path="user_name")]
