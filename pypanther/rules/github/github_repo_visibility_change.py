from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

github_repo_visibility_change_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - Repo Visibility Change",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "repo.access",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Repo disabled",
        expected_result=False,
        log={
            "actor": "cat",
            "action": "repo.disable",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


@panther_managed
class GithubRepoVisibilityChange(Rule):
    id = "Github.Repo.VisibilityChange-prototype"
    display_name = "GitHub Repository Visibility Change"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Exfiltration:Exfiltration Over Web Service"]
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    default_reference = "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility"
    default_severity = Severity.HIGH
    default_description = "Detects when an organization repository visibility changes."
    tests = github_repo_visibility_change_tests

    def rule(self, event):
        return event.get("action") == "repo.access"

    def title(self, event):
        repo_access_link = f"https://github.com/{event.get('repo', '<UNKNOWN_REPO>')}/settings/access"
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] visibility changed. View current visibility here: {repo_access_link}"
