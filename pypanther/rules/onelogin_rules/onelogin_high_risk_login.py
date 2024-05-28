from datetime import timedelta
from typing import List

from panther_detection_helpers.caching import get_counter, increment_counter, reset_counter

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_high_risk_login_tests: List[PantherRuleTest] = [
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
    )
]


class OneLoginHighRiskLogin(PantherRule):
    RuleID = "OneLogin.HighRiskLogin-prototype"
    DisplayName = "OneLogin High Risk Login"
    LogTypes = [LogType.OneLogin_Events]
    Tags = ["OneLogin"]
    Severity = PantherSeverity.Medium
    Description = "A OneLogin user successfully logged in after a failed high-risk login attempt."
    Reference = "https://resources.onelogin.com/OneLogin_RiskBasedAuthentication-WP-v5.pdf"
    Runbook = "Investigate whether this was caused by expected user activity."
    SummaryAttributes = ["account_id", "event_type_id", "user_name", "user_id"]
    Tests = one_login_high_risk_login_tests
    THRESH_TTL = timedelta(minutes=10).total_seconds()

    def rule(self, event):
        # Filter events down to successful and failed login events
        if not event.get("user_id") or str(event.get("event_type_id")) not in ["5", "6"]:
            return False
        event_key = self.get_key(event)
        # check risk associated with this event
        if event.get("risk_score", 0) > 50:
            # a failed authentication attempt with high risk score
            if str(event.get("event_type_id")) == "6":
                # update a counter for this user's failed login attempts with a high risk score
                increment_counter(event_key, event.event_time_epoch() + self.THRESH_TTL)
        # Trigger alert if this user recently
        # failed a high risk login
        if str(event.get("event_type_id")) == "5":
            if get_counter(event_key) > 0:
                reset_counter(event_key)
                return True
        return False

    def get_key(self, event):
        return __name__ + ":" + event.get("user_name", "<UNKNOWN_USER>")

    def title(self, event):
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] successfully logged in after a failed high risk login event"
