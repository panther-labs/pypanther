from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity

github_repo_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        name="GitHub - Repo Created",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "repo.create",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        name="GitHub - Repo Archived",
        expected_result=False,
        log={
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
    id_ = "Github.Repo.Created-prototype"
    display_name = "GitHub Repository Created"
    log_types = [PantherLogType.GitHub_Audit]
    tags = ["GitHub"]
    default_reference = "https://docs.github.com/en/get-started/quickstart/create-a-repo"
    default_severity = PantherSeverity.info
    default_description = "Detects when a repository is created."
    tests = github_repo_created_tests

    def rule(self, event):
        return event.get("action") == "repo.create"

    def title(self, event):
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."
