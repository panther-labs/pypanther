import re
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION
from pypanther.log_types import LogType

zendesk_account_owner_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Zendesk - Owner Changed",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "account",
            "source_label": "Account: Account",
            "action": "update",
            "change_description": "Owner changed from Bob Cat to Mountain Lion",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Admin Role Assigned",
        ExpectedResult=False,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "user",
            "source_label": "Account: Account",
            "action": "update",
            "change_description": "Role changed from End User to Administrator",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
]


class ZendeskAccountOwnerChanged(PantherRule):
    RuleID = "Zendesk.AccountOwnerChanged-prototype"
    DisplayName = "Zendesk Account Owner Changed"
    LogTypes = [LogType.Zendesk_Audit]
    Severity = PantherSeverity.High
    Tags = ["Zendesk", "Privilege Escalation:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    Description = (
        "Only one admin user can be the account owner. Ensure the change in ownership is expected."
    )
    Reference = (
        "https://support.zendesk.com/hc/en-us/articles/4408822084634-Changing-the-account-owner"
    )
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_account_owner_changed_tests
    ZENDESK_OWNER_CHANGED = re.compile(
        "Owner changed from (?P<old_owner>.+) to (?P<new_owner>[^$]+)", re.IGNORECASE
    )

    def rule(self, event):
        if event.get("action", "") == "update" and event.get("source_type", "") == "account":
            return (
                event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("owner changed from ")
            )
        return False

    def title(self, event):
        old_owner = "<UNKNOWN_USER>"
        new_owner = "<UNKNOWN_USER>"
        matches = self.ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
        if matches:
            old_owner = matches.group("old_owner")
            new_owner = matches.group("new_owner")
        return f"zendesk administrative owner changed from {old_owner} to {new_owner}"
