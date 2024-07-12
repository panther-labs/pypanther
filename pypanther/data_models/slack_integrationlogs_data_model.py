from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardSlackIntegrationLogs(PantherDataModel):
    id_: str = "Standard.Slack.IntegrationLogs"
    display_name: str = "Slack Integration Logs"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Slack_IntegrationLogs]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="actor_user", path="user_name")
    ]
