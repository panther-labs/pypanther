from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class OktaGlobalMFADisabled(Rule):
    id = "Okta.Global.MFA.Disabled-prototype"
    display_name = "Okta MFA Globally Disabled"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Identity & Access Management", "DataModel", "Okta", "Defense Evasion:Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    default_severity = Severity.HIGH
    default_description = "An admin user has disabled the MFA requirement for your Okta account"
    default_reference = (
        "https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/about-authenticators.htm"
    )
    default_runbook = "Contact Admin to ensure this was sanctioned activity"
    dedup_period_minutes = 15
    summary_attributes = ["eventType", "severity", "displayMessage", "p_any_ip_addresses"]

    def rule(self, event):
        return event.udm("event_type") == event_type.ADMIN_MFA_DISABLED

    def title(self, event):
        return f"Okta System-wide MFA Disabled by Admin User {event.udm('actor_user')}"

    def alert_context(self, event):
        context = {"user": event.udm("actor_user"), "ip": event.udm("source_ip"), "event": event.get("eventType")}
        return context

    tests = [
        RuleTest(
            name="MFA Disabled",
            expected_result=True,
            log={
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
        RuleTest(
            name="Login Event",
            expected_result=False,
            log={
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
