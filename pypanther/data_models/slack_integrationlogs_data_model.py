from typing import List

from pypanther.base import DataModel, DataModelMapping
from pypanther.log_types import LogType


class StandardSlackIntegrationLogs(DataModel):
    id_: str = "Standard.Slack.IntegrationLogs"
    display_name: str = "Slack Integration Logs"
    enabled: bool = True
    log_types: List[str] = [LogType.Slack_IntegrationLogs]
    mappings: List[DataModelMapping] = [DataModelMapping(name="actor_user", path="user_name")]
