from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_org_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Team Deleted",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "team.destroy",
            "created_at": 1621305118553,
            "data": {"team": "my-org/my-team"},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Org - User Added",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "org.add_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "user": "cat",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Org - User Removed",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "org.remove_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "user": "bob",
        },
    ),
]


class GitHubOrgModified(PantherRule):
    RuleID = "GitHub.Org.Modified-prototype"
    DisplayName = "GitHub User Added or Removed from Org"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    Reference = "https://docs.github.com/en/organizations/managing-membership-in-your-organization"
    Severity = PantherSeverity.Info
    Description = "Detects when a user is added or removed from a GitHub Org."
    Tests = git_hub_org_modified_tests

    def rule(self, event):
        return event.get("action") == "org.add_member" or event.get("action") == "org.remove_member"

    def title(self, event):
        action = event.get("action")
        if event.get("action") == "org.add_member":
            action = "added"
        elif event.get("action") == "org.remove_member":
            action = "removed"
        return f"GitHub.Audit: User [{event.udm('actor_user')}] {action} {event.get('user', '<UNKNOWN_USER>')} to org [{event.get('org', '<UNKNOWN_ORG>')}]"
