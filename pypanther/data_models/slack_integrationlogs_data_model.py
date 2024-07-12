from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardSlackIntegrationLogs(PantherDataModel):
    DataModelID: str = "Standard.Slack.IntegrationLogs"
    DisplayName: str = "Slack Integration Logs"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.Slack_IntegrationLogs]
    Mappings: List[PantherDataModelMapping] = [PantherDataModelMapping(Name="actor_user", Path="user_name")]
