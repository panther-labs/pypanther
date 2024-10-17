import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zendesk import ZENDESK_CHANGE_DESCRIPTION


@panther_managed
class ZendeskAccountOwnerChanged(Rule):
    id = "Zendesk.AccountOwnerChanged-prototype"
    display_name = "Zendesk Account Owner Changed"
    log_types = [LogType.ZENDESK_AUDIT]
    default_severity = Severity.HIGH
    tags = ["Zendesk", "Privilege Escalation:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    default_description = "Only one admin user can be the account owner. Ensure the change in ownership is expected."
    default_reference = "https://support.zendesk.com/hc/en-us/articles/4408822084634-Changing-the-account-owner"
    summary_attributes = ["p_any_ip_addresses"]
    ZENDESK_OWNER_CHANGED = re.compile("Owner changed from (?P<old_owner>.+) to (?P<new_owner>[^$]+)", re.IGNORECASE)

    def rule(self, event):
        if event.get("action", "") == "update" and event.get("source_type", "") == "account":
            return event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("owner changed from ")
        return False

    def title(self, event):
        old_owner = "<UNKNOWN_USER>"
        new_owner = "<UNKNOWN_USER>"
        matches = self.ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
        if matches:
            old_owner = matches.group("old_owner")
            new_owner = matches.group("new_owner")
        return f"zendesk administrative owner changed from {old_owner} to {new_owner}"

    tests = [
        RuleTest(
            name="Zendesk - Owner Changed",
            expected_result=True,
            log={
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
        RuleTest(
            name="Zendesk - Admin Role Assigned",
            expected_result=False,
            log={
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
