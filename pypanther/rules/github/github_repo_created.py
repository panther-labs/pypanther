from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GithubRepoCreated(Rule):
    id = "Github.Repo.Created-prototype"
    display_name = "GitHub Repository Created"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub"]
    default_reference = "https://docs.github.com/en/get-started/quickstart/create-a-repo"
    default_severity = Severity.INFO
    default_description = "Detects when a repository is created."

    def rule(self, event):
        return event.get("action") == "repo.create"

    def title(self, event):
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."

    tests = [
        RuleTest(
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
        RuleTest(
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
