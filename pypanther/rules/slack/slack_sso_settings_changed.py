from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsSSOSettingsChanged(Rule):
    id = "Slack.AuditLogs.SSOSettingsChanged-prototype"
    display_name = "Slack SSO Settings Changed"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Credential Access", "Persistence", "Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0003:T1556", "TA0006:T1556"]}
    default_severity = Severity.HIGH
    default_description = "Detects changes to Single Sign On (SSO) restrictions"
    default_reference = "https://slack.com/intl/en-gb/help/articles/220403548-Manage-single-sign-on-settings"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]

    def rule(self, event):
        return event.get("action") == "pref.sso_setting_changed"

    def alert_context(self, event):
        # TODO: Add details to context
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="SSO Setting Changed",
            expected_result=True,
            log={
                "action": "pref.sso_setting_changed",
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
