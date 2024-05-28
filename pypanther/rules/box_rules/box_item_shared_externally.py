from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_box_helpers import (
    is_box_sdk_enabled,
    lookup_box_file,
    lookup_box_folder,
)
from pypanther.log_types import LogType

box_item_shared_externally_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": 12345678,
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
            "source": {
                "item_name": "regular_file.pdf",
                "item_type": "file",
                "owned_by": {
                    "id": 12345678,
                    "type": "user",
                    "login": "cat@example",
                    "name": "Bob Cat",
                },
                "parent": {
                    "id": 12345,
                    "type": "folder",
                    "etag": 1,
                    "name": "Parent_Folder",
                    "sequence_id": 2,
                },
            },
        },
    )
]


class BoxItemSharedExternally(PantherRule):
    RuleID = "Box.Item.Shared.Externally-prototype"
    DisplayName = "Box item shared externally"
    Enabled = False
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Exfiltration:Exfiltration Over Web Service", "Configuration Required"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    Severity = PantherSeverity.Medium
    Description = "A user has shared an item and it is accessible to anyone with the share link (internal or external to the company). This rule requires that the boxsdk[jwt] be installed in the environment.\n"
    Reference = "https://support.box.com/hc/en-us/articles/4404822772755-Enterprise-Settings-Content-Sharing-Tab"
    Runbook = "Investigate whether this user's activity is expected.\n"
    SummaryAttributes = ["ip_address"]
    Threshold = 10
    Tests = box_item_shared_externally_tests
    ALLOWED_SHARED_ACCESS = {"collaborators", "company"}
    SHARE_EVENTS = {
        "CHANGE_FOLDER_PERMISSION",
        "ITEM_SHARED",
        "ITEM_SHARED_CREATE",
        "ITEM_SHARED_UPDATE",
        "SHARE",
    }

    def rule(self, event):
        # filter events
        if event.get("event_type") not in self.SHARE_EVENTS:
            return False
        # only try to lookup file/folder info if sdk is enabled in the env
        if is_box_sdk_enabled():
            item = self.get_item(event)
            if item is not None and item.get("shared_link"):
                return (
                    deep_get(item, "shared_link", "effective_access")
                    not in self.ALLOWED_SHARED_ACCESS
                )
        return False

    def get_item(self, event):
        item_id = deep_get(event, "source", "item_id", default="")
        user_id = deep_get(event, "source", "owned_by", "id", default="")
        item = {}
        if deep_get(event, "source", "item_type") == "folder":
            item = lookup_box_folder(user_id, item_id)
        elif deep_get(event, "source", "item_type") == "file":
            item = lookup_box_file(user_id, item_id)
        return item

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] shared an item [{deep_get(event, 'source', 'item_name', default='<UNKNOWN_NAME>')}] externally."
