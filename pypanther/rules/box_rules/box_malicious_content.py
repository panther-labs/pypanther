from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import box_parse_additional_details, deep_get
from pypanther.log_types import LogType

box_malicious_content_tests: List[PantherRuleTest] = [
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
        Name="File marked malicious",
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
            "event_type": "FILE_MARKED_MALICIOUS",
            "source": {
                "item_id": "123456789012",
                "item_name": "bad_file.pdf",
                "item_type": "file",
                "owned_by": {
                    "id": "12345678",
                    "type": "user",
                    "login": "cat@example",
                    "name": "Bob",
                },
                "parent": {
                    "id": "12345",
                    "type": "folder",
                    "etag": "1",
                    "name": "Parent_Folder",
                    "sequence_id": "2",
                },
            },
        },
    ),
    PantherRuleTest(
        Name="Malicious Content",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Malicious Content","risk_score":100,"alert_summary":{"upload_activity":{"item_name":"malware.exe"}},"user":{"email":"cat@example"}}}',
            "created_by": {
                "id": 12345678,
                "type": "user",
                "login": "bob@example",
                "name": "Bob Cat",
            },
            "event_type": "SHIELD_ALERT",
            "source": {"id": 12345678, "type": "user", "login": "bob@example"},
        },
    ),
]


class BoxMaliciousContent(PantherRule):
    RuleID = "Box.Malicious.Content-prototype"
    DisplayName = "Malicious Content Detected"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Execution:User Execution"]
    Reports = {"MITRE ATT&CK": ["TA0002:T1204"]}
    Severity = PantherSeverity.High
    Description = "Box has detect malicious content, such as a virus.\n"
    Reference = "https://developer.box.com/guides/events/shield-alert-events/\n"
    Runbook = "Investigate whether this is a false positive or if the virus needs to be contained appropriately.\n"
    SummaryAttributes = ["event_type"]
    Tests = box_malicious_content_tests

    def rule(self, event):
        # enterprise  malicious file alert event
        if event.get("event_type") == "FILE_MARKED_MALICIOUS":
            return True
        # Box Shield will also alert on malicious content
        if event.get("event_type") != "SHIELD_ALERT":
            return False
        alert_details = box_parse_additional_details(event).get("shield_alert", {})
        if alert_details.get("rule_category", "") == "Malicious Content":
            if alert_details.get("risk_score", 0) > 50:
                return True
        return False

    def title(self, event):
        if event.get("event_type") == "FILE_MARKED_MALICIOUS":
            return f"File [{deep_get(event, 'source', 'item_name', default='<UNKNOWN_FILE>')}], owned by [{deep_get(event, 'source', 'owned_by', 'login', default='<UNKNOWN_USER>')}], was marked malicious."
        alert_details = box_parse_additional_details(event).get("shield_alert", {})
        #  pylint: disable=line-too-long
        return f"File [{deep_get(alert_details, 'user', 'email', default='<UNKNOWN_USER>')}], owned by [{deep_get(alert_details, 'alert_summary', 'upload_activity', 'item_name', default='<UNKNOWN_FILE>')}], was marked malicious."
