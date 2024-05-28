from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_tines_helpers import tines_alert_context
from pypanther.log_types import LogType

tines_actions_disabled_changes_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Tines Actions Disabled Change",
        ExpectedResult=True,
        Log={
            "created_at": "2023-05-23 23:16:41",
            "id": 7111111,
            "operation_name": "ActionsDisabledChange",
            "request_ip": "12.12.12.12",
            "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "tenant_id": "8888",
            "user_email": "user@company.com",
            "user_id": "17171",
            "user_name": "user at company dot com",
        },
    ),
    PantherRuleTest(
        Name="Tines Login",
        ExpectedResult=False,
        Log={
            "created_at": "2023-05-17 14:45:19",
            "id": 7888888,
            "operation_name": "Login",
            "request_ip": "12.12.12.12",
            "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "tenant_id": "8888",
            "user_email": "user@company.com",
            "user_id": "17171",
            "user_name": "user at company dot com",
        },
    ),
]


class TinesActionsDisabledChanges(PantherRule):
    RuleID = "Tines.Actions.DisabledChanges-prototype"
    DisplayName = "Tines Actions Disabled Change"
    LogTypes = [LogType.Tines_Audit]
    Tags = ["Tines"]
    Reference = "https://www.tines.com/university/tines-basics/architecture-of-an-action"
    Severity = PantherSeverity.Medium
    Description = "Detections when Tines Actions are set to Disabled Change\n"
    SummaryAttributes = ["user_id", "operation_name", "tenant_id", "request_ip"]
    Tests = tines_actions_disabled_changes_tests
    ACTIONS = ["ActionsDisabledChange"]

    def rule(self, event):
        action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
        return action in self.ACTIONS

    def title(self, event):
        action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
        actor = deep_get(event, "user_email", default="<NO_USERNAME>")
        return f"Tines: {action} by {actor}"

    def alert_context(self, event):
        return tines_alert_context(event)
