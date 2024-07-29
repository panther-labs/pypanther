from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_tines_helpers import tines_alert_context

tines_actions_disabled_changes_tests: list[RuleTest] = [
    RuleTest(
        name="Tines Actions Disabled Change",
        expected_result=True,
        log={
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
    RuleTest(
        name="Tines Login",
        expected_result=False,
        log={
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


@panther_managed
class TinesActionsDisabledChanges(Rule):
    id = "Tines.Actions.DisabledChanges-prototype"
    display_name = "Tines Actions Disabled Change"
    log_types = [LogType.TINES_AUDIT]
    tags = ["Tines"]
    default_reference = "https://www.tines.com/university/tines-basics/architecture-of-an-action"
    default_severity = Severity.MEDIUM
    default_description = "Detections when Tines Actions are set to Disabled Change\n"
    summary_attributes = ["user_id", "operation_name", "tenant_id", "request_ip"]
    tests = tines_actions_disabled_changes_tests
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
