from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_misc_settings_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk Feature Flags changed",
        ExpectedResult=True,
        Log={
            "created": "2023-04-11 23:32:14.173",
            "event": "group.feature_flags.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk User Invite Revoke",
        ExpectedResult=False,
        Log={
            "content": {},
            "created": "2023-04-11 23:32:13.248",
            "event": "org.user.invite.revoke",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
]


class SnykMiscSettings(PantherRule):
    RuleID = "Snyk.Misc.Settings-prototype"
    DisplayName = "Snyk Miscellaneous Settings"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Reference = "https://docs.snyk.io/snyk-admin/manage-settings"
    Severity = PantherSeverity.Low
    Description = "Detects when Snyk settings that lack a clear security impact are changed\n"
    SummaryAttributes = ["event"]
    Tests = snyk_misc_settings_tests
    ACTIONS = ["group.cloud_config.settings.edit", "group.feature_flags.edit"]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        operation = "<NO_OPERATION>"
        action = deep_get(event, "event", default="<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            operation = ".".join(action.split(".")[1:]).title()
        return f"Snyk: [{group_or_org}] Setting [{operation}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    def dedup(self, event):
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}{deep_get(event, 'event', default='<NO_EVENT>')}"
