from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

box_large_number_downloads_tests: List[PantherRuleTest] = [
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
        Name="User Download",
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
            "event_type": "DOWNLOAD",
            "source": {
                "id": "12345678",
                "type": "user",
                "login": "user@example",
                "name": "Bob Cat",
            },
        },
    ),
]


class BoxLargeNumberDownloads(PantherRule):
    RuleID = "Box.Large.Number.Downloads-prototype"
    DisplayName = "Box Large Number of Downloads"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Exfiltration:Exfiltration Over Web Service"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    Severity = PantherSeverity.Low
    Description = (
        "A user has exceeded the threshold for number of downloads within a single time frame.\n"
    )
    Reference = (
        "https://support.box.com/hc/en-us/articles/360043697134-Download-Files-and-Folders-from-Box"
    )
    Runbook = "Investigate whether this user's download activity is expected.  Investigate the cause of this download activity.\n"
    SummaryAttributes = ["ip_address"]
    Threshold = 100
    Tests = box_large_number_downloads_tests

    def rule(self, event):
        return event.get("event_type") == "DOWNLOAD"

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] exceeded threshold for number of downloads in the configured time frame."
