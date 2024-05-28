from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

box_large_number_permission_updates_tests: List[PantherRuleTest] = [
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
        Name="User Permission Change",
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
            "event_type": "CHANGE_FOLDER_PERMISSION",
            "source": {
                "id": "12345678",
                "type": "user",
                "login": "user@example",
                "name": "Bob Cat",
            },
        },
    ),
    PantherRuleTest(
        Name="User Shares Item",
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
            "event_type": "ITEM_SHARED_CREATE",
            "source": {
                "id": "12345678",
                "type": "user",
                "login": "user@example",
                "name": "Bob Cat",
            },
        },
    ),
]


class BoxLargeNumberPermissionUpdates(PantherRule):
    RuleID = "Box.Large.Number.Permission.Updates-prototype"
    DisplayName = "Box Large Number of Permission Changes"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Privilege Escalation:Abuse Elevation Control Mechanism"]
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Severity = PantherSeverity.Low
    Description = "A user has exceeded the threshold for number of folder permission changes within a single time frame.\n"
    Reference = (
        "https://support.box.com/hc/en-us/articles/360043697254-Understanding-Folder-Permissions"
    )
    Runbook = "Investigate whether this user's activity is expected.\n"
    SummaryAttributes = ["ip_address"]
    Threshold = 100
    Tests = box_large_number_permission_updates_tests
    PERMISSION_UPDATE_EVENT_TYPES = {
        "CHANGE_FOLDER_PERMISSION",
        "ITEM_SHARED_CREATE",
        "ITEM_SHARED",
        "SHARE",
    }

    def rule(self, event):
        return event.get("event_type") in self.PERMISSION_UPDATE_EVENT_TYPES

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] exceeded threshold for number of permission changes in the configured time frame."
