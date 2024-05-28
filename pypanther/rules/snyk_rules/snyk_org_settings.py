from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_org_settings_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="placeholder",
        ExpectedResult=True,
        Log={
            "content": {
                "after": {
                    "integrationSettings": {
                        "autoDepUpgradeIgnoredDependencies": [],
                        "autoDepUpgradeLimit": 5,
                        "autoRemediationPrs": {"usePatchRemediation": True},
                        "isMajorUpgradeEnabled": True,
                        "manualRemediationPrs": {"useManualPatchRemediation": True},
                        "pullRequestAssignment": {
                            "assignees": ["github_handle", "github_handle2"],
                            "enabled": True,
                            "type": "manual",
                        },
                        "pullRequestTestEnabled": True,
                        "reachableVulns": {},
                    }
                },
                "before": {
                    "integrationSettings": {
                        "autoDepUpgradeIgnoredDependencies": [],
                        "autoDepUpgradeLimit": 5,
                        "autoRemediationPrs": {"usePatchRemediation": True},
                        "isMajorUpgradeEnabled": True,
                        "manualRemediationPrs": {"useManualPatchRemediation": True},
                        "pullRequestAssignment": {
                            "assignees": ["github_handle", "github_handle2"],
                            "enabled": True,
                            "type": "manual",
                        },
                        "reachableVulns": {},
                    }
                },
                "integrationPublicId": "81111111-cccc-4eee-bfff-3ccccccccccc",
                "interface": "ui",
            },
            "created": "2023-03-24 14:53:51.334",
            "event": "org.integration.settings.edit",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
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
]


class SnykOrgSettings(PantherRule):
    RuleID = "Snyk.Org.Settings-prototype"
    DisplayName = "Snyk Org Settings"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Reference = "https://docs.snyk.io/snyk-admin/manage-settings/organization-general-settings"
    Severity = PantherSeverity.Medium
    Description = (
        "Detects when Snyk Organization settings, like Integrations and Webhooks, are changed\n"
    )
    SummaryAttributes = ["event"]
    Tests = snyk_org_settings_tests
    ACTIONS = [
        "org.integration.create",
        "org.integration.delete",
        "org.integration.edit",
        "org.integration.settings.edit",
        "org.request_access_settings.edit",
        "org.target.create",
        "org.target.delete",
        "org.webhook.add",
        "org.webhook.delete",
    ]

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
