from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION
from pypanther.log_types import LogType

zendesk_user_suspension_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Zendesk - Suspension Enabled",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "user_setting",
            "source_label": "Suspension state: Bob Cat",
            "action": "create",
            "change_description": "Suspended",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Suspension Disabled",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "user_setting",
            "source_label": "Suspension state: Bob Cat",
            "action": "update",
            "change_description": "Unsuspended",
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
            "source_label": "Bob Cat",
            "action": "update",
            "change_description": "Role changed from End User to Administrator",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
]


class ZendeskUserSuspension(PantherRule):
    RuleID = "Zendesk.UserSuspension-prototype"
    DisplayName = "Zendesk User Suspension Status Changed"
    LogTypes = [LogType.Zendesk_Audit]
    Tags = ["Zendesk", "Impact:Account Access Removal"]
    Reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    Severity = PantherSeverity.High
    Description = "A user's Zendesk suspension status was changed."
    Runbook = "Ensure the user's suspension status is appropriate."
    Reference = "https://support.zendesk.com/hc/en-us/articles/4408889293978-Suspending-a-user#:~:text=select%20Unsuspend%20access.-,Identifying%20suspended%20users,name%20on%20the%20Customers%20page"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_user_suspension_tests
    USER_SUSPENSION_ACTIONS = {"create", "update"}

    def rule(self, event):
        return (
            event.get("source_type") == "user_setting"
            and event.get("action", "") in self.USER_SUSPENSION_ACTIONS
            and ("suspended" in event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower())
        )

    def title(self, event):
        suspension_status = event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower()
        user = event.get("source_label", "<UNKNOWN_USER>").split(":")
        if len(user) > 1:
            user = user[1].strip()
        return f"Actor user [{event.udm('actor_user')}] {suspension_status} user [{user}]"

    def severity(self, event):
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "suspended":
            return "INFO"
        return "HIGH"
