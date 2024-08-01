from datetime import timedelta

from panther_detection_helpers.caching import get_counter, increment_counter, reset_counter

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

one_login_high_risk_login_tests: list[RuleTest] = [
    RuleTest(
        name="Normal Login Event",
        expected_result=False,
        log={
            "event_type_id": "6",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


@panther_managed
class OneLoginHighRiskLogin(Rule):
    id = "OneLogin.HighRiskLogin-prototype"
    display_name = "OneLogin High Risk Login"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin"]
    default_severity = Severity.MEDIUM
    default_description = "A OneLogin user successfully logged in after a failed high-risk login attempt."
    default_reference = "https://resources.onelogin.com/OneLogin_RiskBasedAuthentication-WP-v5.pdf"
    default_runbook = "Investigate whether this was caused by expected user activity."
    summary_attributes = ["account_id", "event_type_id", "user_name", "user_id"]
    tests = one_login_high_risk_login_tests
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
