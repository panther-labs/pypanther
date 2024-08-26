from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

duo_user_denied_anomalous_push_tests: list[RuleTest] = [
    RuleTest(
        name="anomalous_push_occurred",
        expected_result=True,
        log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "anomalous_push",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    RuleTest(
        name="good_auth",
        expected_result=False,
        log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_approved",
            "result": "success",
            "user": {"name": "example@example.io"},
        },
    ),
    RuleTest(
        name="denied_old_creds",
        expected_result=False,
        log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "out_of_date",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
]


@panther_managed
class DUOUserDeniedAnomalousPush(Rule):
    id = "DUO.User.Denied.AnomalousPush-prototype"
    display_name = "Duo User Auth Denied For Anomalous Push"
    dedup_period_minutes = 15
    log_types = [LogType.DUO_AUTHENTICATION]
    tags = ["Duo"]
    default_severity = Severity.MEDIUM
    default_description = "A Duo authentication was denied due to an anomalous 2FA push.\n"
    default_reference = "https://duo.com/docs/adminapi#authentication-logs"
    default_runbook = "Follow up with the user to confirm they intended several pushes in quick succession."
    tests = duo_user_denied_anomalous_push_tests

    def rule(self, event):
        return event.get("reason") == "anomalous_push" and event.get("result") == "denied"

    def title(self, event):
        user = deep_get(event, "user", "name", default="Unknown")
        return f"Duo Auth denied due to an anomalous 2FA push for [{user}]"

    def alert_context(self, event):
        return {
            "factor": event.get("factor"),
            "reason": event.get("reason"),
            "user": deep_get(event, "user", "name", default=""),
            "os": deep_get(event, "access_device", "os", default=""),
            "ip_access": deep_get(event, "access_device", "ip", default=""),
            "ip_auth": deep_get(event, "auth_device", "ip", default=""),
            "application": deep_get(event, "application", "name", default=""),
        }
