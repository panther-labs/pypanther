from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

asana_workspace_email_domain_added_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="new domain",
        ExpectedResult=True,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@example.io",
                "gid": "12345",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:30:26.15",
            "details": {"new_value": "test.com"},
            "event_category": "admin_settings",
            "event_type": "workspace_associated_email_domain_added",
            "gid": "12345",
            "resource": {"gid": "12345", "name": "Example IO", "resource_type": "workspace"},
        },
    ),
    PantherRuleTest(
        Name="other event",
        ExpectedResult=False,
        Log={
            "actor": {
                "actor_type": "user",
                "email": "homer.simpson@example.io",
                "gid": "12345",
                "name": "Homer Simpson",
            },
            "context": {
                "client_ip_address": "12.12.12.12",
                "context_type": "web",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            },
            "created_at": "2022-12-16 19:30:26.15",
            "details": {"new_value": "anyone", "old_value": "admins_only"},
            "event_category": "admin_settings",
            "event_type": "workspace_guest_invite_permissions_changed",
            "gid": "12345",
            "resource": {"gid": "12345", "name": "Example IO", "resource_type": "workspace"},
        },
    ),
]


class AsanaWorkspaceEmailDomainAdded(PantherRule):
    Description = "A new email domain has been added to an Asana workspace. Reviewer should validate that the new domain is a part of the organization. "
    DisplayName = "Asana Workspace Email Domain Added"
    Reference = "https://help.asana.com/hc/en-us/articles/15901227439515-Email-domain-management-for-Asana-organizations"
    Severity = PantherSeverity.Low
    LogTypes = [LogType.Asana_Audit]
    RuleID = "Asana.Workspace.Email.Domain.Added-prototype"
    Tests = asana_workspace_email_domain_added_tests

    def rule(self, event):
        return event.get("event_type") == "workspace_associated_email_domain_added"

    def title(self, event):
        workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
        domain = deep_get(event, "details", "new_value", default="<DOMAIN_NOT_FOUND>")
        actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
        return f"Asana new email domain [{domain}] added to Workspace [{workspace}] by [{actor}]."
