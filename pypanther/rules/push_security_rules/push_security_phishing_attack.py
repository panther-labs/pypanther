from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

push_security_phishing_attack_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Phishing Detected - Block Mode",
        ExpectedResult=True,
        Log={
            "id": "c478966c-f927-411c-b919-179832d3d50c",
            "new": {
                "appType": "OKTA",
                "browser": "CHROME",
                "employee": {
                    "chatopsEnabled": True,
                    "creationTimestamp": 1698669223.0,
                    "department": "Security Engineering",
                    "email": "john.hill@example.com",
                    "firstName": "John",
                    "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "lastName": "Hill",
                    "licensed": True,
                    "location": "New York",
                },
                "mode": "BLOCK",
                "os": "WINDOWS",
                "referrerUrl": "https://statics.teams.cdn.office.net/",
                "sourceIpAddress": "8.158.25.38",
                "url": "https://evil.com/okta.php",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
            },
            "object": "PASSWORD_PHISHING",
            "timestamp": 1698604061.0,
            "version": "1",
        },
    ),
    PantherRuleTest(
        Name="Phishing Detected - Monitor Mode",
        ExpectedResult=True,
        Log={
            "id": "c478966c-f927-411c-b919-179832d3d50c",
            "new": {
                "appType": "OKTA",
                "browser": "CHROME",
                "employee": {
                    "chatopsEnabled": True,
                    "creationTimestamp": 1698669223.0,
                    "department": "Security Engineering",
                    "email": "john.hill@example.com",
                    "firstName": "John",
                    "id": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "lastName": "Hill",
                    "licensed": True,
                    "location": "New York",
                },
                "mode": "MONITOR",
                "os": "WINDOWS",
                "referrerUrl": "https://statics.teams.cdn.office.net/",
                "sourceIpAddress": "8.158.25.38",
                "url": "https://evil.com/okta.php",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
            },
            "object": "PASSWORD_PHISHING",
            "timestamp": 1698604061.0,
            "version": "1",
        },
    ),
]


class PushSecurityPhishingAttack(PantherRule):
    RuleID = "Push.Security.Phishing.Attack-prototype"
    DisplayName = "Push Security Phishing Attack"
    LogTypes = [LogType.PushSecurity_AttackDetection]
    Severity = PantherSeverity.High
    Tests = push_security_phishing_attack_tests

    def rule(self, event):
        if event.get("object") == "PASSWORD_PHISHING":
            return True
        return False

    def severity(self, event):
        if event.deep_get("new", "mode") != "BLOCK":
            return "HIGH"
        return "LOW"

    def title(self, event):
        app_type = event.deep_get("new", "appType")
        employee_email = event.deep_get("new", "employee", "email")
        new_mode = event.deep_get("new", "mode")
        return f"Phishing attack on app {app_type} user {employee_email}.              Attack detected in mode {new_mode}."
