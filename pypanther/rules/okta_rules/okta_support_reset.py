from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, okta_alert_context
from pypanther.log_types import LogType

okta_support_reset_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Support Reset Credential",
        ExpectedResult=True,
        Log={
            "uuid": "12343",
            "published": "2021-11-29 18:56:40.014",
            "eventType": "user.account.reset_password",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user.config.user_status.password_reset",
            "displayMessage": "Fired when the user's Okta password is reset",
            "actor": {
                "alternateId": "system@okta.com",
                "displayName": "system@okta.com",
                "id": "1111111",
                "type": "User",
            },
            "client": {
                "device": "Computer",
                "ipAddress": "1.1.1.1",
                "userAgent": {"browser": "CHROME", "os": "Mac OS X"},
                "zone": "null",
            },
            "outcome": {"result": "SUCCESS"},
            "target": [
                {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "1111111",
                    "type": "User",
                }
            ],
            "transaction": {"detail": {}, "id": "unknown", "type": "WEB"},
            "p_log_type": "Okta.SystemLog",
        },
    ),
    PantherRuleTest(
        Name="Reset by Company Admin",
        ExpectedResult=False,
        Log={
            "uuid": "2aaaaaaaaaabbbbbbbbbbbbddddddddddd",
            "eventType": "user.account.reset_password",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user.config.user_status.password_reset",
            "displayMessage": "Fired when the user's Okta password is reset",
            "actor": {
                "alternateId": "marge@springfield.gov",
                "displayName": "Marge Simpson",
                "id": "1111",
                "type": "User",
            },
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "postalCode": "80014",
                    "state": "Debated",
                },
                "ipAddress": "1.1.1.1",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                },
                "zone": "null",
            },
            "outcome": {"result": "SUCCESS"},
            "target": [
                {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "1.1.1.1",
                    "type": "User",
                }
            ],
            "transaction": {"detail": {}, "id": "1111", "type": "WEB"},
            "p_log_type": "Okta.SystemLog",
        },
    ),
]


class OktaSupportReset(PantherRule):
    RuleID = "Okta.Support.Reset-prototype"
    DisplayName = "Okta Support Reset Credential"
    LogTypes = [LogType.Okta_SystemLog]
    Tags = [
        "Identity & Access Management",
        "DataModel",
        "Okta",
        "Initial Access:Trusted Relationship",
    ]
    Reports = {"MITRE ATT&CK": ["TA0001:T1199"]}
    Severity = PantherSeverity.High
    Description = "A Password or MFA factor was reset by Okta Support"
    Reference = "https://help.okta.com/en/prod/Content/Topics/Directory/get-support.htm#:~:text=Visit%20the%20Okta%20Help%20Center,1%2D800%2D219%2D0964"
    Runbook = "Contact Admin to ensure this was sanctioned activity"
    DedupPeriodMinutes = 15
    SummaryAttributes = ["eventType", "severity", "p_any_ip_addresses"]
    Tests = okta_support_reset_tests
    OKTA_SUPPORT_RESET_EVENTS = [
        "user.account.reset_password",
        "user.mfa.factor.update",
        "system.mfa.factor.deactivate",
        "user.mfa.attempt_bypass",
    ]

    def rule(self, event):
        if event.get("eventType") not in self.OKTA_SUPPORT_RESET_EVENTS:
            return False
        return (
            deep_get(event, "actor", "alternateId") == "system@okta.com"
            and deep_get(event, "transaction", "id") == "unknown"
            and (deep_get(event, "userAgent", "rawUserAgent") is None)
            and (deep_get(event, "client", "geographicalContext", "country") is None)
        )

    def title(self, event):
        return f"Okta Support Reset Password or MFA for user {event.udm('actor_user')}"

    def alert_context(self, event):
        return okta_alert_context(event)
