from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

okta_global_mfa_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="MFA Disabled",
        ExpectedResult=True,
        Log={
            "published": "2022-03-22 14:21:53.225",
            "eventType": "system.mfa.factor.deactivate",
            "version": "0",
            "severity": "HIGH",
            "actor": {
                "alternateId": "homer@springfield.gov",
                "displayName": "Homer Simpson",
                "id": "111111",
                "type": "User",
            },
            "client": {
                "device": "Computer",
                "ipAddress": "1.1.1.1",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36",
                },
                "zone": "null",
            },
            "p_log_type": "Okta.SystemLog",
        },
    ),
    PantherRuleTest(
        Name="Login Event",
        ExpectedResult=False,
        Log={
            "published": "2022-03-22 14:21:53.225",
            "eventType": "user.session.start",
            "version": "0",
            "severity": "INFO",
            "actor": {
                "alternateId": "homer@springfield.gov",
                "displayName": "Homer Simpson",
                "id": "111111",
                "type": "User",
            },
            "client": {
                "device": "Computer",
                "ipAddress": "1.1.1.1",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36",
                },
                "zone": "null",
            },
            "p_log_type": "Okta.SystemLog",
        },
    ),
]


class OktaGlobalMFADisabled(PantherRule):
    RuleID = "Okta.Global.MFA.Disabled-prototype"
    DisplayName = "Okta MFA Globally Disabled"
    LogTypes = [LogType.Okta_SystemLog]
    Tags = [
        "Identity & Access Management",
        "DataModel",
        "Okta",
        "Defense Evasion:Modify Authentication Process",
    ]
    Reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    Severity = PantherSeverity.High
    Description = "An admin user has disabled the MFA requirement for your Okta account"
    Reference = "https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/about-authenticators.htm"
    Runbook = "Contact Admin to ensure this was sanctioned activity"
    DedupPeriodMinutes = 15
    SummaryAttributes = ["eventType", "severity", "displayMessage", "p_any_ip_addresses"]
    Tests = okta_global_mfa_disabled_tests

    def rule(self, event):
        return event.udm("event_type") == event_type.ADMIN_MFA_DISABLED

    def title(self, event):
        return f"Okta System-wide MFA Disabled by Admin User {event.udm('actor_user')}"

    def alert_context(self, event):
        context = {
            "user": event.udm("actor_user"),
            "ip": event.udm("source_ip"),
            "event": event.get("eventType"),
        }
        return context
