from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

github_repo_visibility_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Repo Visibility Change",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "repo.access",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Repo disabled",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "repo.disable",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GithubRepoVisibilityChange(PantherRule):
    RuleID = "Github.Repo.VisibilityChange-prototype"
    DisplayName = "GitHub Repository Visibility Change"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Exfiltration:Exfiltration Over Web Service"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    Reference = "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility"
    Severity = PantherSeverity.High
    Description = "Detects when an organization repository visibility changes."
    Tests = github_repo_visibility_change_tests

    def rule(self, event):
        return event.get("action") == "repo.access"

    def title(self, event):
        repo_access_link = (
            f"https://github.com/{event.get('repo', '<UNKNOWN_REPO>')}/settings/access"
        )
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] visibility changed. View current visibility here: {repo_access_link}"
