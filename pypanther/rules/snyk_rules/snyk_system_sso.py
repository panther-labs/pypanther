from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_system_sso_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk System SSO Setting event happened",
        ExpectedResult=True,
        Log={
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
            "event": "group.sso.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "content": {"unknown": "contents"},
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


class SnykSystemSSO(PantherRule):
    RuleID = "Snyk.System.SSO-prototype"
    DisplayName = "Snyk System SSO Settings Changed"
    LogTypes = [LogType.Snyk_GroupAudit]
    Tags = ["Snyk"]
    Severity = PantherSeverity.High
    Description = "Detects Snyk SSO Settings have been changed. The reference URL from Snyk indicates that these events are likely to originate exclusively from Snyk Support.\n"
    Reference = "https://docs.snyk.io/user-and-group-management/setting-up-sso-for-authentication/set-up-snyk-single-sign-on-sso"
    SummaryAttributes = ["event", "p_any_ip_addresses", "p_any_emails"]
    Tests = snyk_system_sso_tests
    ACTIONS = [
        "group.sso.auth0_connection.create",
        "group.sso.auth0_connection.edit",
        "group.sso.create",
        "group.sso.edit",
    ]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        return f"Snyk: System SSO Setting event [{deep_get(event, 'event', default='<NO_EVENT>')}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)
