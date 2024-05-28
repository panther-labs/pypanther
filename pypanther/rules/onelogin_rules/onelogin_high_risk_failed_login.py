from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_high_risk_failed_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={
            "event_type_id": "6",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="Failed High Risk Login",
        ExpectedResult=True,
        Log={
            "event_type_id": "6",
            "risk_score": 55,
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginHighRiskFailedLogin(PantherRule):
    RuleID = "OneLogin.HighRiskFailedLogin-prototype"
    DisplayName = "OneLogin Failed High Risk Login"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin"]
    Severity = PantherSeverity.Low
    Description = (
        "A OneLogin attempt with a high risk factor (>50) resulted in a failed authentication."
    )
    Reference = "https://resources.onelogin.com/OneLogin_RiskBasedAuthentication-WP-v5.pdf"
    Runbook = "Investigate why this user login is tagged as high risk as well as whether this was caused by expected user activity."
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_high_risk_failed_login_tests

    def rule(self, event):
        # check risk associated with this event
        if event.get("risk_score", 0) > 50:
            # a failed authentication attempt with high risk
            return str(event.get("event_type_id")) == "6"
        return False

    def title(self, event):
        return (
            f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] failed a high risk login attempt"
        )
