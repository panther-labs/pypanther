import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import zendesk_get_roles

zendesk_user_role_changed_tests: list[RuleTest] = [
    RuleTest(
        name="Zendesk - Role Changed",
        expected_result=True,
        log={
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
            "source_label": "Bob Cat",
            "action": "update",
            "change_description": "Role changed from End User to Administrator",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
]


@panther_managed
class ZendeskUserRoleChanged(Rule):
    id = "Zendesk.UserRoleChanged-prototype"
    display_name = "Zendesk User Role Changed"
    log_types = [LogType.ZENDESK_AUDIT]
    default_severity = Severity.INFO
    default_description = "A user's Zendesk role was changed"
    default_reference = (
        "https://support.zendesk.com/hc/en-us/articles/4408824375450-Setting-roles-and-access-in-Zendesk-Admin-Center"
    )
    summary_attributes = ["p_any_ip_addresses"]
    tests = zendesk_user_role_changed_tests

    def rule(self, event):
        if event.get("source_type") == "user" and event.get("action") == "update":
            # admin roles have their own handling
            if event.udm("event_type") != event_type.ADMIN_ROLE_ASSIGNED:
                _, new_role = zendesk_get_roles(event)
                return bool(new_role)
        return False

    def title(self, event):
        old_role, new_role = zendesk_get_roles(event)
        return (
            f"Actor user [{event.udm('actor_user')}] changed [{event.udm('user')}] role from {old_role} to {new_role}"
        )
