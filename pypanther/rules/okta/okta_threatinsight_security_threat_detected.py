from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaThreatInsightSecurityThreatDetected(Rule):
    default_description = "Okta ThreatInsight identified request from potentially malicious IP address"
    default_reference = (
        "https://help.okta.com/en-us/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.htm"
    )
    display_name = "Okta ThreatInsight Security Threat Detected"
    default_severity = Severity.HIGH
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "Okta.ThreatInsight.Security.Threat.Detected-prototype"

    def severity_from_threat_string(self, threat_detection):
        # threat detection is a string but contains json data
        # can contain multiple threats detected with multiple severities
        # return highest found severity
        if "CRITICAL" in threat_detection:
            return "CRITICAL"
        if "HIGH" in threat_detection:
            return "HIGH"
        if "MEDIUM" in threat_detection:
            return "MEDIUM"
        if "LOW" in threat_detection:
            return "LOW"
        if "INFO" in threat_detection:
            return "INFO"
        return "MEDIUM"

    def rule(self, event):
        return event.get("eventtype") == "security.threat.detected"

    def title(self, event):
        return f"Okta: ThreatInsight identified potentially malicious behavior for [{event.get('actor', {}).get('displayName', '<display-name-not-found>')}]"

    def severity(self, event):
        outcome = event.deep_get("outcome", "result", default="<OUTCOME_NOT_FOUND>")
        if outcome == "DENY":
            return "INFO"
        threat_detection = (
            event.get("debugcontext", {}).get("debugData", {}).get("threatDetections", "<threat-detection-not-found>")
        )
        return self.severity_from_threat_string(threat_detection)

    def alert_context(self, event):
        return okta_alert_context(event)

    tests = [
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "homer.simpson@duff.com",
                    "displayName": "Homer Simpson",
                    "id": "00abc456",
                    "type": "User",
                },
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "abc12345"},
                "client": {
                    "device": "Unknown",
                    "ipAddress": "1.2.3.4",
                    "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Chrome"},
                    "zone": "null",
                },
                "debugcontext": {"debugData": {}},
                "eventtype": "application.integration.rate_limit_exceeded",
                "legacyeventtype": "app.api.error.rate.limit.exceeded",
                "outcome": {"result": "SUCCESS"},
                "published": "2022-06-10 17:19:58.423",
                "request": {},
                "securitycontext": {},
                "severity": "INFO",
                "target": [{"alternateId": "App ", "displayName": "App", "id": "12345", "type": "AppInstance"}],
                "transaction": {"detail": {}, "id": "sdfg", "type": "JOB"},
                "uuid": "aaa-bb-ccc",
                "version": "0",
            },
        ),
        RuleTest(
            name="Threat Detected Event - Deny",
            expected_result=True,
            log={
                "actor": {"alternateId": "unknown", "displayName": "1.2.3.4", "id": "1.2.3.4", "type": "IP address"},
                "authenticationcontext": {"authenticationStep": 0},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Dallas",
                        "country": "United States",
                        "geolocation": {"lat": 32.7908, "lon": -96.8336},
                        "postalCode": "75207",
                        "state": "Texas",
                    },
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Windows 10",
                        "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugcontext": {
                    "debugData": {
                        "dtHash": "abcsadfjsald",
                        "requestId": "alsdjflasf",
                        "requestUri": "/oauth2/v1/authorize",
                        "threatDetections": '{"Login failures with high unknown users count":"HIGH","Password Spray":"HIGH","Login Failures":"MEDIUM"}',
                        "threatSuspected": "true",
                        "url": "/oauth2/v1/authorize",
                    },
                },
                "displaymessage": "Request from suspicious actor",
                "eventtype": "security.threat.detected",
                "legacyeventtype": "security.threat.detected",
                "outcome": {
                    "reason": "Password Spray, Login failures with high unknown users count, Login Failures",
                    "result": "DENY",
                },
                "published": "2022-12-14 19:16:32.015",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Dallas",
                                "country": "United States",
                                "geolocation": {"lat": 32.7908, "lon": -96.8336},
                                "postalCode": "75207",
                                "state": "Texas",
                                "ip": "1.2.3.4",
                                "version": "V4",
                            },
                        },
                    ],
                },
                "securitycontext": {
                    "asNumber": 62240,
                    "asOrg": "packethub s.a.",
                    "domain": ".",
                    "isProxy": False,
                    "isp": "clouvider limited",
                },
                "severity": "WARN",
                "transaction": {"detail": {}, "id": "asdfjaslf", "type": "WEB"},
                "uuid": "asdfa-1234-asdfdas",
                "version": "0",
            },
        ),
        RuleTest(
            name="Threat Detected Event - Success",
            expected_result=True,
            log={
                "actor": {"alternateId": "unknown", "displayName": "1.2.3.4", "id": "1.2.3.4", "type": "IP address"},
                "authenticationcontext": {"authenticationStep": 0},
                "client": {
                    "device": "Computer",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Windows 10",
                        "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugcontext": {
                    "debugData": {
                        "dtHash": "abcsadfjsald",
                        "requestId": "alsdjflasf",
                        "requestUri": "/oauth2/v1/authorize",
                        "threatDetections": '{"Login failures with high unknown users count":"HIGH","Password Spray":"HIGH","Login Failures":"MEDIUM"}',
                        "threatSuspected": "true",
                        "url": "/oauth2/v1/authorize",
                    },
                },
                "displaymessage": "Request from suspicious actor",
                "eventtype": "security.threat.detected",
                "legacyeventtype": "security.threat.detected",
                "outcome": {
                    "reason": "Password Spray, Login failures with high unknown users count, Login Failures",
                    "result": "SUCCESS",
                },
                "published": "2022-12-14 19:16:32.015",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Dallas",
                                "country": "United States",
                                "geolocation": {"lat": 32.7908, "lon": -96.8336},
                                "postalCode": "75207",
                                "state": "Texas",
                                "ip": "1.2.3.4",
                                "version": "V4",
                            },
                        },
                    ],
                },
                "securitycontext": {
                    "asNumber": 62240,
                    "asOrg": "packethub s.a.",
                    "domain": ".",
                    "isProxy": False,
                    "isp": "clouvider limited",
                },
                "severity": "WARN",
                "transaction": {"detail": {}, "id": "asdfjaslf", "type": "WEB"},
                "uuid": "asdfa-1234-asdfdas",
                "version": "0",
            },
        ),
    ]
