from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get

box_brute_force_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
        },
    ),
    PantherRuleTest(
        Name="Login Failed",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "FAILED_LOGIN",
            "source": {"id": "12345678", "type": "user", "name": "Bob Cat"},
        },
    ),
]


class BoxBruteForceLogin(PantherRule):
    RuleID = "Box.Brute.Force.Login-prototype"
    DisplayName = "--DEPRECATED -- Box Brute Force Login"
    Enabled = False
    LogTypes = ["Box.Event"]
    Tags = ["Box"]
    Severity = Severity.Medium
    Description = "A Box user was denied access more times than the configured threshold.\n"
    Threshold = 10
    DedupPeriodMinutes = 10
    Reference = "https://support.box.com/hc/en-us/articles/360043695174-Logging-in-to-Box"
    Runbook = "Analyze the IP they came from, and other actions taken before/after.  Check if this user eventually authenticated successfully.\n"
    SummaryAttributes = ["event_type", "ip_address"]
    Tests = box_brute_force_login_tests

    def rule(self, event):
        return event.get("event_type") == "FAILED_LOGIN"

    def title(self, event):
        return f"User [{deep_get(event, 'source', 'name', default='<UNKNOWN_USER>')}] has exceeded the failed login threshold."
