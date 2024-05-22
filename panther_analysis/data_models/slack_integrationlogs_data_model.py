from typing import List
from panther_analysis.base import PantherDataModel, PantherDataModelMapping


class StandardSlackIntegrationLogs(PantherDataModel):
    DataModelID: str = "Standard.Slack.IntegrationLogs"
    DisplayName: str = "Slack Integration Logs"
    Enabled: bool = True
    LogTypes: List[str] = ["Slack.IntegrationLogs"]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="actor_user", Path="user_name")
    ]
