from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

github_repo_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Repo Created",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "repo.create",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Repo Archived",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "repo.archived",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GithubRepoCreated(PantherRule):
    RuleID = "Github.Repo.Created-prototype"
    DisplayName = "GitHub Repository Created"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub"]
    Reference = "https://docs.github.com/en/get-started/quickstart/create-a-repo"
    Severity = PantherSeverity.Info
    Description = "Detects when a repository is created."
    Tests = github_repo_created_tests

    def rule(self, event):
        return event.get("action") == "repo.create"

    def title(self, event):
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."
