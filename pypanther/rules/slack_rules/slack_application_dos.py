from datetime import timedelta
from json import dumps

from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, slack_alert_context

slack_audit_logs_application_do_s_tests: list[RuleTest] = [
    RuleTest(
        name="User Session Reset - First time",
        expected_result=False,
        mocks=[
            RuleMock(object_name="get_string_set", return_value=""),
            RuleMock(object_name="put_string_set", return_value=""),
        ],
        log={
            "action": "user_session_reset_by_admin",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "T01234N56GB",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace-1",
                    "id": "T01234N56GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
        },
    ),
    RuleTest(
        name="User Session Reset - Multiple Times",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_string_set", return_value='{"time":"2021-06-08 22:24:43"}'),
            RuleMock(object_name="put_string_set", return_value=""),
        ],
        log={
            "action": "user_session_reset_by_admin",
            "actor": {
                "type": "user",
                "user": {
                    "email": "user@example.com",
                    "id": "W012J3FEWAU",
                    "name": "primary-owner",
                    "team": "T01234N56GB",
                },
            },
            "context": {
                "ip_address": "1.2.3.4",
                "location": {
                    "domain": "test-workspace-1",
                    "id": "T01234N56GB",
                    "name": "test-workspace-1",
                    "type": "workspace",
                },
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            },
        },
    ),
]


@panther_managed
class SlackAuditLogsApplicationDoS(Rule):
    id = "Slack.AuditLogs.ApplicationDoS-prototype"
    display_name = "Slack Denial of Service"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Impact", "Endpoint Denial of Service", "Application Exhaustion Flood"]
    reports = {"MITRE ATT&CK": ["TA0040:T1499.003"]}
    default_severity = Severity.CRITICAL
    default_description = (
        "Detects when slack admin invalidates user session(s) more than once in a 24 hour period which can lead to DoS"
    )
    default_reference = "https://slack.com/intl/en-gb/help/articles/115005223763-Manage-session-duration-#pro-and-business+-subscriptions-2"
    threshold = 60
    summary_attributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_application_do_s_tests
    DENIAL_OF_SERVICE_ACTIONS = [
        "bulk_session_reset_by_admin",
        "user_session_invalidated",
        "user_session_reset_by_admin",
    ]

    def rule(self, event):
        # Only evaluate actions that could be used for a DoS
        if event.get("action") not in self.DENIAL_OF_SERVICE_ACTIONS:
            return False
        # Generate a unique cache key for each user
        user_key = self.gen_key(event)
        # Retrieve prior entries from the cache, if any
        last_reset = get_string_set(user_key)
        # Store the reset info for future use
        self.store_reset_info(user_key, event)
        # If this is the first reset for the user, don't alert
        if not last_reset:
            return False
        return True

    def alert_context(self, event):
        return slack_alert_context(event)

    def gen_key(self, event):
        return f"Slack.AuditLogs.ApplicationDoS{deep_get(event, 'entity', 'user', 'name')}"

    def store_reset_info(self, key, event):
        # Map the user to the most recent reset
        put_string_set(
            key,
            [dumps({"time": event.get("p_event_time")})],
            epoch_seconds=event.event_time_epoch() + timedelta(days=1).total_seconds(),
        )
