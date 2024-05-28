from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_config import config
from pypanther.log_types import LogType

box_event_triggered_externally_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example.com",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
        },
    ),
    PantherRuleTest(
        Name="Previewed Anonymously",
        ExpectedResult=True,
        Log={
            "created_by": {"id": "2", "type": "user", "name": "Unknown User"},
            "event_type": "PREVIEW",
            "type": "event",
            "ip_address": "1.2.3.4",
        },
    ),
    PantherRuleTest(
        Name="Missing Created By",
        ExpectedResult=False,
        Log={"event_type": "PREVIEW", "type": "event", "ip_address": "1.2.3.4"},
    ),
]


class BoxEventTriggeredExternally(PantherRule):
    RuleID = "Box.Event.Triggered.Externally-prototype"
    DisplayName = "Box event triggered by unknown or external user"
    Enabled = False
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Exfiltration:Exfiltration Over Web Service", "Configuration Required"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    Severity = PantherSeverity.Medium
    Description = "An external user has triggered a box enterprise event.\n"
    Reference = (
        "https://support.box.com/hc/en-us/articles/8391393127955-Using-the-Enterprise-Event-Stream"
    )
    Runbook = "Investigate whether this user's activity is expected.\n"
    SummaryAttributes = ["ip_address"]
    Threshold = 10
    Tests = box_event_triggered_externally_tests
    DOMAINS = {"@" + domain for domain in config.ORGANIZATION_DOMAINS}

    def rule(self, event):
        # Check that all events are triggered by internal users
        if event.get("event_type") not in ("FAILED_LOGIN", "SHIELD_ALERT"):
            user = event.get("created_by", {})
            # user id 2 indicates an anonymous user
            if user.get("id", "") == "2":
                return True
            return bool(
                user.get("login")
                and (not any((user.get("login", "").endswith(x) for x in self.DOMAINS)))
            )
        return False

    def title(self, event):
        return f"External user [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] triggered a box event."
