from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

okta_support_access_tests: list[RuleTest] = [
    RuleTest(
        name="Support Access Granted",
        expected_result=True,
        log={
            "published": "2022-03-22 14:21:53.225",
            "eventType": "user.session.impersonation.grant",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user.impersonation.grant.enabled",
            "displayMessage": "Enable impersonation grant",
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


@panther_managed
class OktaSupportAccess(Rule):
    id = "Okta.Support.Access-prototype"
    display_name = "Okta Support Access Granted"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Identity & Access Management", "DataModel", "Okta", "Initial Access:Trusted Relationship"]
    reports = {"MITRE ATT&CK": ["TA0001:T1199"]}
    default_severity = Severity.MEDIUM
    default_description = "An admin user has granted access to Okta Support to your account"
    default_reference = "https://help.okta.com/en/prod/Content/Topics/Settings/settings-support-access.htm"
    default_runbook = "Contact Admin to ensure this was sanctioned activity"
    dedup_period_minutes = 15
    summary_attributes = ["eventType", "severity", "displayMessage", "p_any_ip_addresses"]
    tests = okta_support_access_tests
    OKTA_SUPPORT_ACCESS_EVENTS = ["user.session.impersonation.grant", "user.session.impersonation.initiate"]

    def rule(self, event):
        return event.get("eventType") in self.OKTA_SUPPORT_ACCESS_EVENTS

    def title(self, event):
        return f"Okta Support Access Granted by {event.udm('actor_user')}"

    def alert_context(self, event):
        context = {"user": event.udm("actor_user"), "ip": event.udm("source_ip"), "event": event.get("eventType")}
        return context
