from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsPotentiallyMaliciousFileShared(Rule):
    id = "Slack.AuditLogs.PotentiallyMaliciousFileShared-prototype"
    display_name = "Slack Potentially Malicious File Shared"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Initial Access", "Phishing", "Spearphising Attachment"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566.001"]}
    default_severity = Severity.CRITICAL
    default_description = "Detects when a potentially malicious file is shared within Slack"
    default_reference = "https://threatpost.com/slack-remote-file-hijacking-malware/144871/"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]

    def rule(self, event):
        return event.get("action") == "file_malicious_content_detected"

    def alert_context(self, event):
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="Malicious Content Detected",
            expected_result=True,
            log={
                "action": "file_malicious_content_detected",
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
            name="User Logout",
            expected_result=False,
            log={
                "action": "user_logout",
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
                "date_create": "2022-07-28 15:22:32",
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
            },
        ),
    ]
