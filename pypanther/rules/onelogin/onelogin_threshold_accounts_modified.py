from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OneLoginThresholdAccountsModified(Rule):
    id = "OneLogin.ThresholdAccountsModified-prototype"
    display_name = "OneLogin Multiple Accounts Modified"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Impact:Account Access Removal"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    default_description = "Possible Denial of Service detected. Threshold for user account password changes exceeded.\n"
    threshold = 10
    dedup_period_minutes = 10
    default_reference = "https://en.wikipedia.org/wiki/Denial-of-service_attack"
    default_runbook = "Determine if this is normal user-cleanup activity."
    summary_attributes = ["account_id", "user_name", "user_id"]

    def rule(self, event):
        # filter events; event type 11 is an actor_user changed user password
        return str(event.get("event_type_id")) == "11"

    def title(self, event):
        return f"User [{event.get('actor_user_name', '<UNKNOWN_USER>')}] has exceeded the user account password change threshold"

    tests = [
        RuleTest(
            name="Normal User Activated Event",
            expected_result=False,
            log={
                "event_type_id": "16",
                "actor_user_id": 654321,
                "actor_user_name": "Mountain Lion",
                "user_id": 123456,
                "user_name": "Bob Cat",
            },
        ),
        RuleTest(
            name="User Password Changed Event",
            expected_result=True,
            log={
                "event_type_id": "11",
                "actor_user_id": 654321,
                "actor_user_name": "Mountain Lion",
                "user_id": 123456,
                "user_name": "Bob Cat",
            },
        ),
    ]
