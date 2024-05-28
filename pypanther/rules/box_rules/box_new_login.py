from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

box_new_login_tests: List[PantherRuleTest] = [
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
        Name="New Login Event",
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
            "event_type": "ADD_LOGIN_ACTIVITY_DEVICE",
            "source": {"id": "12345678", "type": "user", "login": "user@example"},
        },
    ),
]


class BoxNewLogin(PantherRule):
    RuleID = "Box.New.Login-prototype"
    DisplayName = "Box New Login"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = PantherSeverity.Info
    Description = "A user logged in from a new device.\n"
    Reference = "https://support.box.com/hc/en-us/articles/360043691914-Controlling-Devices-Used-to-Access-Box"
    Runbook = "Investigate whether this is a valid user login.\n"
    SummaryAttributes = ["ip_address"]
    Tests = box_new_login_tests

    def rule(self, event):
        # ADD_LOGIN_ACTIVITY_DEVICE
        #  detect when a user logs in from a device not previously seen
        return event.get("event_type") == "ADD_LOGIN_ACTIVITY_DEVICE"

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] logged in from a new device."
