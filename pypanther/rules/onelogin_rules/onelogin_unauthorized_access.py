from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_unauthorized_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Event",
        ExpectedResult=False,
        Log={
            "event_type_id": "8",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "app_name": "confluence",
        },
    ),
    PantherRuleTest(
        Name="User Unauthorized Access Event",
        ExpectedResult=True,
        Log={
            "event_type_id": "90",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "app_name": "confluence",
        },
    ),
]


class OneLoginUnauthorizedAccess(PantherRule):
    RuleID = "OneLogin.UnauthorizedAccess-prototype"
    DisplayName = "OneLogin Unauthorized Access"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin", "Lateral Movement:Use Alternate Authentication Material"]
    Reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    Severity = PantherSeverity.Medium
    Description = (
        "A OneLogin user was denied access to an app more times than the configured threshold."
    )
    Threshold = 10
    DedupPeriodMinutes = 10
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010420"
    Runbook = "Analyze the user activity and actions."
    SummaryAttributes = ["account_id", "user_name", "user_id", "app_name"]
    Tests = one_login_unauthorized_access_tests

    def rule(self, event):
        # filter events; event type 90 is an unauthorized application access event id
        return str(event.get("event_type_id")) == "90"

    def title(self, event):
        return f"User [{event.get('user_name', '<UNKNOWN_USER>')}] has exceeded the unauthorized application access attempt threshold"
