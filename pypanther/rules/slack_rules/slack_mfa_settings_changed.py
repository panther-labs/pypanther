from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import slack_alert_context
from pypanther.log_types import LogType

slack_audit_logs_mfa_settings_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="MFA Auth Changed",
        ExpectedResult=True,
        Log={
            "action": "pref.two_factor_auth_changed",
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
    PantherRuleTest(
        Name="User Logout",
        ExpectedResult=False,
        Log={
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


class SlackAuditLogsMFASettingsChanged(PantherRule):
    RuleID = "Slack.AuditLogs.MFASettingsChanged-prototype"
    DisplayName = "Slack MFA Settings Changed"
    LogTypes = [LogType.Slack_AuditLogs]
    Tags = [
        "Slack",
        "Defense Evasion",
        "Modify Authentication Process",
        "Multi-Factor Authentication",
    ]
    Reports = {"MITRE ATT&CK": ["TA0005:T1556.006"]}
    Severity = PantherSeverity.High
    Description = "Detects changes to Multi-Factor Authentication requirements"
    Reference = (
        "https://slack.com/intl/en-gb/help/articles/204509068-Set-up-two-factor-authentication"
    )
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = slack_audit_logs_mfa_settings_changed_tests

    def rule(self, event):
        return event.get("action") == "pref.two_factor_auth_changed"

    def alert_context(self, event):
        # TODO: Add details to context
        return slack_alert_context(event)
