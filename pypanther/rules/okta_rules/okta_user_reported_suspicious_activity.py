from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import okta_alert_context

okta_user_reported_suspicious_activity_tests: list[RuleTest] = [
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00abc123",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "100-abc-9999"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "geolocation": {"lat": 20, "lon": -25},
                    "postalCode": "12345",
                    "state": "Ohio",
                },
                "ipAddress": "1.3.2.4",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                },
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "requestId": "AbCdEf12G",
                    "requestUri": "/api/v1/users/AbCdEfG/lifecycle/reset_factors",
                    "url": "/api/v1/users/AbCdEfG/lifecycle/reset_factors?",
                },
            },
            "displaymessage": "Reset all factors for user",
            "eventtype": "user.mfa.factor.reset_all",
            "legacyeventtype": "core.user.factor.reset_all",
            "outcome": {"result": "SUCCESS"},
            "published": "2022-06-22 18:18:29.015",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "city": "Springfield",
                            "country": "United States",
                            "geolocation": {"lat": 20, "lon": -25},
                            "postalCode": "12345",
                            "state": "Ohio",
                        },
                        "ip": "1.3.2.4",
                        "version": "V4",
                    },
                ],
            },
            "securitycontext": {
                "asNumber": 701,
                "asOrg": "verizon",
                "domain": "verizon.net",
                "isProxy": False,
                "isp": "verizon",
            },
            "severity": "INFO",
            "target": [
                {
                    "alternateId": "peter.griffin@company.com",
                    "displayName": "Peter Griffin",
                    "id": "0002222AAAA",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "ABcDeFgG", "type": "WEB"},
            "uuid": "AbC-123-XyZ",
            "version": "0",
        },
    ),
    RuleTest(
        name="Suspicious Report Event",
        expected_result=True,
        log={
            "actor": {
                "alternateId": "homer.simpson@duff.com",
                "displayName": "Homer Simpson",
                "id": "00ABC123",
                "type": "User",
            },
            "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "aaa1234"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Springfield",
                    "country": "United States",
                    "geolocation": {"lat": 30, "lon": -55},
                    "postalCode": "12345",
                    "state": "Texas",
                },
                "ipAddress": "1.2.3.4",
                "userAgent": {
                    "browser": "CHROME",
                    "os": "Mac OS X",
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                },
                "zone": "null",
            },
            "debugcontext": {
                "debugData": {
                    "dtHash": "ab123542525",
                    "requestId": "A1S05S00000",
                    "requestUri": "/api/internal/users/me/report-suspicious-activity",
                    "suspiciousActivityBrowser": "SAFARI",
                    "suspiciousActivityEventCity": "Springfield",
                    "suspiciousActivityEventCountry": "United States",
                    "suspiciousActivityEventId": "aaa-123-bbb",
                    "suspiciousActivityEventIp": "9.8.7.6",
                    "suspiciousActivityEventLatitude": "30.000",
                    "suspiciousActivityEventLongitude": "-55.000",
                    "suspiciousActivityEventState": "Texas",
                    "suspiciousActivityEventTransactionId": "ABC12345",
                    "suspiciousActivityEventType": "system.email.new_device_notification.sent_message",
                    "suspiciousActivityOs": "Mac OS X (iPhone)",
                    "suspiciousActivityTimestamp": "2022-12-14T15:58:50.347Z",
                    "url": "/api/internal/users/me/report-suspicious-activity?i=aaaaaa",
                },
            },
            "displaymessage": "User report suspicious activity",
            "eventtype": "user.account.report_suspicious_activity_by_enduser",
            "legacyeventtype": "core.user.account.report_suspicious_activity_by_enduser",
            "outcome": {"result": "SUCCESS"},
            "published": "2022-12-14 15:58:58.851",
            "request": {
                "ipChain": [
                    {
                        "geographicalContext": {
                            "city": "Austin",
                            "country": "United States",
                            "geolocation": {"lat": 30, "lon": -55},
                            "postalCode": "12345",
                            "state": "Texas",
                        },
                        "ip": "9.8.7.6",
                        "version": "V4",
                    },
                ],
            },
            "securitycontext": {
                "asNumber": 11427,
                "asOrg": "charter communications inc",
                "domain": "spectrum.com",
                "isProxy": False,
                "isp": "charter communications inc",
            },
            "severity": "WARN",
            "target": [
                {
                    "alternateId": "homer.simpson@duff.com",
                    "displayName": "Homer Simpson",
                    "id": "01234",
                    "type": "User",
                },
            ],
            "transaction": {"detail": {}, "id": "1234ABC", "type": "WEB"},
            "uuid": "ABC1234",
            "version": "0",
        },
    ),
]


@panther_managed
class OktaUserReportedSuspiciousActivity(Rule):
    default_description = "Suspicious Activity Reporting provides an end user with the option to report unrecognized activity from an account activity email notification.\nThis detection alerts when a user marks the raised activity as suspicious."
    default_reference = "https://help.okta.com/en-us/Content/Topics/Security/suspicious-activity-reporting.htm"
    display_name = "Okta User Reported Suspicious Activity"
    default_severity = Severity.HIGH
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.User.Reported.Suspicious.Activity-prototype"
    tests = okta_user_reported_suspicious_activity_tests

    def rule(self, event):
        return event.get("eventtype") == "user.account.report_suspicious_activity_by_enduser"

    def title(self, event):
        reported_event_type = (
            event.get("debugcontext", {})
            .get("debugData", {})
            .get("suspiciousActivityEventType", "<event-type-not-found>")
        )
        return f"Okta: [{event.get('actor', {}).get('alternateId', '<id-not-found>')}] reported suspicious account activity [{reported_event_type}]."

    def alert_context(self, event):
        return okta_alert_context(event)
