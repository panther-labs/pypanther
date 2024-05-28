from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_system_external_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk External Access Allowed By External Parties - Enabled",
        ExpectedResult=True,
        Log={
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "event": "group.request_access_settings.edit",
            "content": {"after": {"isEnabled": True}, "before": {}},
            "created": "2023-03-03T19:52:01.628Z",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk External Access Allowed By External Parties - Disabled",
        ExpectedResult=True,
        Log={
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "event": "group.request_access_settings.edit",
            "content": {"after": {}, "before": {"isEnabled": True}},
            "created": "2023-03-03T20:52:01.628Z",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group SSO Membership sync",
        ExpectedResult=False,
        Log={
            "content": {
                "addAsOrgAdmin": [],
                "addAsOrgCollaborator": ["group.name"],
                "addAsOrgCustomRole": [],
                "addAsOrgRestrictedCollaborator": [],
                "removedOrgMemberships": [],
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "2023-03-15 13:13:13.133",
            "event": "group.sso.membership.sync",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
        },
    ),
]


class SnykSystemExternalAccess(PantherRule):
    RuleID = "Snyk.System.ExternalAccess-prototype"
    DisplayName = "Snyk System External Access Settings Changed"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Severity = PantherSeverity.High
    Description = (
        "Detects when Snyk Settings that control access for external parties have been changed.\n"
    )
    Runbook = "This action in the Snyk Audit logs indicate that the setting for allowing external parties to request access to your Snyk installation have changed.\n"
    Reference = (
        "https://docs.snyk.io/snyk-admin/manage-users-and-permissions/organization-access-requests"
    )
    SummaryAttributes = ["event"]
    Tests = snyk_system_external_access_tests
    ACTIONS = ["group.request_access_settings.edit", "org.request_access_settings.edit"]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
        action = deep_get(event, "event", default="<NO_EVENT>")
        if "." in action:
            action = action.split(".")[0].title()
        return f"Snyk: [{action}] External Access settings have been modified to PermitExternalUsers:[{current_setting}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
        a_c["current_setting"] = current_setting
        return a_c

    def dedup(self, event):
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}"

    def severity(self, event):
        current_setting = deep_get(event, "content", "after", "isEnabled", default=False)
        if current_setting:
            return "HIGH"
        return "INFO"
