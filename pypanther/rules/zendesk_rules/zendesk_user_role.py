from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import zendesk_get_roles
from pypanther.log_types import LogType

zendesk_user_role_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Zendesk - Role Changed",
        ExpectedResult=True,
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
            "change_description": "Role changed from Administrator to End User",
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


class ZendeskUserRoleChanged(PantherRule):
    RuleID = "Zendesk.UserRoleChanged-prototype"
    DisplayName = "Zendesk User Role Changed"
    LogTypes = [LogType.Zendesk_Audit]
    Severity = PantherSeverity.Info
    Description = "A user's Zendesk role was changed"
    Reference = "https://support.zendesk.com/hc/en-us/articles/4408824375450-Setting-roles-and-access-in-Zendesk-Admin-Center"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_user_role_changed_tests

    def rule(self, event):
        if event.get("source_type") == "user" and event.get("action") == "update":
            # admin roles have their own handling
            if event.udm("event_type") != event_type.ADMIN_ROLE_ASSIGNED:
                _, new_role = zendesk_get_roles(event)
                return bool(new_role)
        return False

    def title(self, event):
        old_role, new_role = zendesk_get_roles(event)
        return f"Actor user [{event.udm('actor_user')}] changed [{event.udm('user')}] role from {old_role} to {new_role}"
