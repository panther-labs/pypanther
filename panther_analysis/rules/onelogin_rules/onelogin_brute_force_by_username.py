from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity

one_login_brute_force_by_username_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Login Event",
        ExpectedResult=False,
        Log={
            "event_type_id": "8",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
    PantherRuleTest(
        Name="Failed Login Event",
        ExpectedResult=True,
        Log={
            "event_type_id": "6",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
        },
    ),
]


class OneLoginBruteForceByUsername(PantherRule):
    RuleID = "OneLogin.BruteForceByUsername-prototype"
    DisplayName = "--DEPRECATED-- OneLogin Brute Force Username"
    Enabled = False
    LogTypes = ["OneLogin.Events"]
    Tags = ["OneLogin", "Credential Access:Brute Force"]
    Severity = Severity.Medium
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Description = "A OneLogin user was denied access more times than the configured threshold."
    Threshold = 10
    DedupPeriodMinutes = 10
    Reference = "https://www.fortinet.com/resources/cyberglossary/brute-force-attack#:~:text=A%20brute%20force%20attack%20is,and%20organizations'%20systems%20and%20networks."
    Runbook = "Analyze the IP they came from, and other actions taken before/after.  Check if this user eventually authenticated successfully."
    SummaryAttributes = ["account_id", "user_name", "user_id"]
    Tests = one_login_brute_force_by_username_tests

    def rule(self, event):
        # filter events; event type 6 is a failed authentication
        return str(event.get("event_type_id")) == "6"

    def title(self, event):
        return f"User [{event.get('user_name', '<UNKNOWN_USER>')}] has exceeded the failed logins threshold"
