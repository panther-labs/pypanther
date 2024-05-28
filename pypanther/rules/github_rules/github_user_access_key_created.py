from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_user_access_key_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - User Access Key Created",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "public_key.create",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - User Access Key Deleted",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "public_key.delete",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GitHubUserAccessKeyCreated(PantherRule):
    RuleID = "GitHub.User.AccessKeyCreated-prototype"
    DisplayName = "GitHub User Access Key Created"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Persistence:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1078"]}
    Reference = "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"
    Severity = PantherSeverity.Info
    Description = "Detects when a GitHub user access key is created."
    Tests = git_hub_user_access_key_created_tests

    def rule(self, event):
        return event.get("action") == "public_key.create"

    def title(self, event):
        return f"User [{event.udm('actor_user')}] created a new ssh key"
