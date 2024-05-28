from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_project_settings_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk Org Project Stop Monitor",
        ExpectedResult=True,
        Log={
            "content": {
                "origin": "github",
                "target": {
                    "branch": "some-branch",
                    "id": 222222222,
                    "name": "repo-name",
                    "owner": "github-org",
                },
                "targetFile": "go.mod",
                "type": "gomodules",
            },
            "created": "2023-03-30 15:38:18.58",
            "event": "org.project.stop_monitor",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "projectId": "05555555-8555-2333-5aaa-600000000000",
            "userId": "05555555-3333-4ddd-8ccc-75555555555",
        },
    ),
    PantherRuleTest(
        Name="Project Ignore Create",
        ExpectedResult=True,
        Log={
            "content": {
                "created": "2023-03-20T12:23:06.356Z",
                "ignorePath": "*",
                "ignoredBy": {"id": "05555555-3333-4ddd-8ccc-75555555555"},
                "issueId": "SNYK-JS-UNDICI-3323845",
                "reason": "dev dependency",
                "reasonType": "wont-fix",
            },
            "created": "2023-03-20 12:23:08.363",
            "event": "org.project.ignore.create",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "projectId": "05555555-8555-2333-5aaa-600000000000",
            "userId": "05555555-3333-4ddd-8ccc-75555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group SSO Membership sync",
        ExpectedResult=False,
        Log={
            "content": {},
            "created": "2023-03-15 13:13:13.133",
            "event": "group.sso.membership.sync",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
        },
    ),
]


class SnykProjectSettings(PantherRule):
    RuleID = "Snyk.Project.Settings-prototype"
    DisplayName = "Snyk Project Settings"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Reference = "https://docs.snyk.io/snyk-admin/introduction-to-snyk-projects/view-and-edit-project-settings"
    Severity = PantherSeverity.Medium
    Description = "Detects when Snyk Project settings are changed\n"
    SummaryAttributes = ["event"]
    Tests = snyk_project_settings_tests
    # The bodies of these actions are quite diverse.
    # When projects are added, the logged detail is the sourceOrgId.
    # org.project.stop_monitor is logged for individual files
    #   that are ignored.
    # AND the equivalent for licenses",
    ACTIONS = [
        "org.sast_settings.edit",
        "org.project.attributes.edit",
        "org.project.add",
        "org.project.delete",
        "org.project.edit",
        "org.project.fix_pr.manual_open",
        "org.project.ignore.create",
        "org.project.ignore.delete",
        "org.project.ignore.edit",
        "org.project.monitor",
        "org.project.pr_check.edit",
        "org.project.remove",
        "org.project.settings.delete",
        "org.project.settings.edit",
        "org.project.stop_monitor",
        "org.license_rule.create",
        "org.license_rule.delete",
        "org.license_rule.edit",
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
        return f"Snyk: [{group_or_org}] [{operation}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        # merge event in for the alert_context
        a_c.update(event)
        return a_c

    def dedup(self, event):
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}{deep_get(event, 'event', default='<NO_EVENT>')}"

    def severity(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        if action == "org.project.fix_pr.manual_open":
            return "INFO"
        return "LOW"
