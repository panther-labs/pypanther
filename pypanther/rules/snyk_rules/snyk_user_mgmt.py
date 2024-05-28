from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_user_management_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk User Removed",
        ExpectedResult=True,
        Log={
            "content": {
                "email": "user@example.com",
                "force": True,
                "name": "user@example.com",
                "userPublicId": "cccccccc-3333-4ddd-8ccc-755555555555",
                "username": "user@example.com",
            },
            "created": "2023-04-11 23:32:14.173",
            "event": "org.user.remove",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk User Invite Revoke",
        ExpectedResult=True,
        Log={
            "content": {},
            "created": "2023-04-11 23:32:13.248",
            "event": "org.user.invite.revoke",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group User add",
        ExpectedResult=True,
        Log={
            "content": {
                "role": "Group Member",
                "rolePublicId": "65555555-c000-4ddd-2222-cfffffffffff",
                "userPublicId": "cccccccc-3333-4ddd-8ccc-755555555555",
            },
            "created": "2023-04-11 23:14:55.572",
            "event": "group.user.add",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk System SSO Setting event happened",
        ExpectedResult=False,
        Log={
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
            "event": "group.sso.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "content": {"unknown": "contents"},
        },
    ),
    PantherRuleTest(
        Name="SAML User Added",
        ExpectedResult=False,
        Log={
            "content": {
                "role": "Org Collaborator",
                "rolePublicId": "beeeeeee-dddd-4444-aaaa-133333333333",
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "2023-06-01 03:14:42.776",
            "event": "org.user.add",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
]


class SnykUserManagement(PantherRule):
    RuleID = "Snyk.User.Management-prototype"
    DisplayName = "Snyk User Management"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Severity = PantherSeverity.Medium
    Description = "Detects when Snyk Users are changed\n"
    Runbook = "These actions in the Snyk Audit logs indicate that a User has been created/deleted/modified.\n"
    Reference = "https://docs.snyk.io/snyk-admin/manage-users-and-permissions/member-roles"
    SummaryAttributes = ["event"]
    Tests = snyk_user_management_tests
    ACTIONS = [
        "group.user.add",
        "group.user.provision.accept",
        "group.user.provision.create",
        "group.user.provision.delete",
        "group.user.remove",
        "org.user.add",
        "org.user.invite",
        "org.user.invite.accept",
        "org.user.invite.revoke",
        "org.user.invite_link.accept",
        "org.user.invite_link.create",
        "org.user.invite_link.revoke",
        "org.user.leave",
        "org.user.provision.accept",
        "org.user.provision.create",
        "org.user.provision.delete",
        "org.user.remove",
    ]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        # for org.user.add/group.user.add via SAML/SCIM
        # the attributes .userId and .content.publicUserId
        # have the same value
        if action.endswith(".user.add"):
            target_user = deep_get(event, "content", "userPublicId", default="<NO_CONTENT_UID>")
            actor = deep_get(event, "userId", default="<NO_USERID>")
            if target_user == actor:
                return False
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        operation = "<NO_OPERATION>"
        action = deep_get(event, "event", default="<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            operation = ".".join(action.split(".")[2:]).title()
        return f"Snyk: [{group_or_org}] User [{operation}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    def dedup(self, event):
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}{deep_get(event, 'event', default='<NO_EVENT>')}"

    def severity(self, event):
        role = deep_get(event, "content", "after", "role", default=None)
        if not role and "afterRoleName" in deep_get(event, "content", default={}):
            role = deep_get(event, "content", "afterRoleName", default=None)
        if role == "ADMIN":
            return "CRITICAL"
        return "MEDIUM"
