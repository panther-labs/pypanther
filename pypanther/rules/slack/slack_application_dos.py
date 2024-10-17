from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsApplicationDoS(Rule):
    id = "Slack.AuditLogs.ApplicationDoS-prototype"
    display_name = "Slack Denial of Service"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Impact", "Endpoint Denial of Service", "Application Exhaustion Flood"]
    reports = {"MITRE ATT&CK": ["TA0040:T1499.003"]}
    default_severity = Severity.CRITICAL
    default_description = "Detects when slack admin invalidates user session(s). If it happens more than once in a 24 hour period it can lead to DoS"
    default_reference = "https://slack.com/intl/en-gb/help/articles/115005223763-Manage-session-duration-#pro-and-business+-subscriptions-2"
    dedup_period_minutes = 1440
    threshold = 60
    summary_attributes = ["action", "p_any_ip_addresses", "p_any_emails"]
    DENIAL_OF_SERVICE_ACTIONS = [
        "bulk_session_reset_by_admin",
        "user_session_invalidated",
        "user_session_reset_by_admin",
    ]

    def rule(self, event):
        # Only evaluate actions that could be used for a DoS
        if event.get("action") not in self.DENIAL_OF_SERVICE_ACTIONS:
            return False
        return True

    def dedup(self, event):
        return f"Slack.AuditLogs.ApplicationDoS{event.deep_get('entity', 'user', 'name')}"

    def alert_context(self, event):
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="User Session Reset",
            expected_result=True,
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
            name="Other action",
            expected_result=False,
            log={
                "action": "organization_created",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace",
                        "id": "T01234N56GB",
                        "name": "test-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
            },
        ),
    ]
