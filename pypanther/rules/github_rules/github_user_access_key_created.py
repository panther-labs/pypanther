from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_hub_user_access_key_created_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - User Access Key Created",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "public_key.create",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - User Access Key Deleted",
        expected_result=False,
        log={
            "actor": "cat",
            "action": "public_key.delete",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


@panther_managed
class GitHubUserAccessKeyCreated(Rule):
    id = "GitHub.User.AccessKeyCreated-prototype"
    display_name = "GitHub User Access Key Created"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Persistence:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0003:T1078"]}
    default_reference = "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"
    default_severity = Severity.INFO
    default_description = "Detects when a GitHub user access key is created."
    tests = git_hub_user_access_key_created_tests

    def rule(self, event):
        return event.get("action") == "public_key.create"

    def title(self, event):
        return f"User [{event.udm('actor_user')}] created a new ssh key"
