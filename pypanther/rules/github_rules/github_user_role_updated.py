from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_user_role_updated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Member Updated",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "org.update_member",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "bob",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Member Invited",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "org.invite_member",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "bob",
        },
    ),
]


class GitHubUserRoleUpdated(PantherRule):
    RuleID = "GitHub.User.RoleUpdated-prototype"
    DisplayName = "GitHub User Role Updated"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Persistence:Account Manipulation"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Reference = "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization"
    Severity = PantherSeverity.High
    Description = (
        "Detects when a GitHub user role is upgraded to an admin or downgraded to a member"
    )
    Tests = git_hub_user_role_updated_tests

    def rule(self, event):
        return event.get("action") == "org.update_member"

    def title(self, event):
        return f"Org owner [{event.udm('actor_user')}] updated user's [{event.get('user')}] role ('admin' or 'member')"
