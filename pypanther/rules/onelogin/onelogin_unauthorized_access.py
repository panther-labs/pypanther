from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OneLoginUnauthorizedAccess(Rule):
    id = "OneLogin.UnauthorizedAccess-prototype"
    display_name = "OneLogin Unauthorized Access"
    log_types = [LogType.ONELOGIN_EVENTS]
    tags = ["OneLogin", "Lateral Movement:Use Alternate Authentication Material"]
    reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    default_severity = Severity.MEDIUM
    default_description = "A OneLogin user was denied access to an app more times than the configured threshold."
    threshold = 10
    dedup_period_minutes = 10
    default_reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010420"
    default_runbook = "Analyze the user activity and actions."
    summary_attributes = ["account_id", "user_name", "user_id", "app_name"]

    def rule(self, event):
        # filter events; event type 90 is an unauthorized application access event id
        return str(event.get("event_type_id")) == "90"

    def title(self, event):
        return f"User [{event.get('user_name', '<UNKNOWN_USER>')}] has exceeded the unauthorized application access attempt threshold"

    tests = [
        RuleTest(
            name="Normal Event",
            expected_result=False,
            log={"event_type_id": "8", "user_id": 123456, "user_name": "Bob Cat", "app_name": "confluence"},
        ),
        RuleTest(
            name="User Unauthorized Access Event",
            expected_result=True,
            log={"event_type_id": "90", "user_id": 123456, "user_name": "Bob Cat", "app_name": "confluence"},
        ),
    ]
