from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import slack_alert_context

slack_audit_logs_org_deleted_tests: list[RuleTest] = [
    RuleTest(
        name="Organization Deleted",
        expected_result=True,
        log={
            "action": "organization_deleted",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
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
    RuleTest(
        name="Organization Created",
        expected_result=False,
        log={
            "action": "organization_created",
            "actor": {
                "type": "user",
                "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
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


@panther_managed
class SlackAuditLogsOrgDeleted(Rule):
    id = "Slack.AuditLogs.OrgDeleted-prototype"
    display_name = "Slack Organization Deleted"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Impact", "Account Access Removal"]
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when a Slack organization is deleted"
    default_reference = "https://slack.com/intl/en-gb/help/articles/204067366-Delete-a-workspace"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tests = slack_audit_logs_org_deleted_tests

    def rule(self, event):
        return event.get("action") == "organization_deleted"

    def alert_context(self, event):
        return slack_alert_context(event)
