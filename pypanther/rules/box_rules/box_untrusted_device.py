from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

box_untrusted_device_tests: List[PantherRuleTest] = [
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
            "event_type": "DEVICE_TRUST_CHECK_FAILED",
            "source": {"id": "12345678", "type": "user", "login": "user@example"},
        },
    ),
]


class BoxUntrustedDevice(PantherRule):
    RuleID = "Box.Untrusted.Device-prototype"
    DisplayName = "Box Untrusted Device Login"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = PantherSeverity.Info
    Description = "A user attempted to login from an untrusted device.\n"
    Reference = "https://support.box.com/hc/en-us/articles/360044194993-Setting-Up-Device-Trust-Security-Requirements"
    Runbook = "Investigate whether this is a valid user attempting to login to box.\n"
    SummaryAttributes = ["ip_address"]
    Tests = box_untrusted_device_tests

    def rule(self, event):
        # DEVICE_TRUST_CHECK_FAILED
        #  detect when a user attempts to login from an untrusted device
        return event.get("event_type") == "DEVICE_TRUST_CHECK_FAILED"

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] attempted to login from an untrusted device."
