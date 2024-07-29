from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_hub_repo_hook_modified_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - Webhook Created",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "hook.create",
            "data": {"hook_id": 111222333444555, "events": ["fork", "public", "pull_request", "push", "repository"]},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Webhook Deleted",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "hook.destroy",
            "data": {"hook_id": 111222333444555, "events": ["fork", "public", "pull_request", "push", "repository"]},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Non Webhook Event",
        expected_result=False,
        log={
            "actor": "cat",
            "action": "org.invite_member",
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
]


@panther_managed
class GitHubRepoHookModified(Rule):
    id = "GitHub.Repo.HookModified-prototype"
    display_name = "GitHub Web Hook Modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Exfiltration:Automated Exfiltration"]
    reports = {"MITRE ATT&CK": ["TA0010:T1020"]}
    default_reference = "https://docs.github.com/en/webhooks/about-webhooks"
    default_severity = Severity.INFO
    default_description = "Detects when a web hook is added, modified, or deleted in an org repository."
    tests = git_hub_repo_hook_modified_tests

    def rule(self, event):
        return event.get("action").startswith("hook.")

    def title(self, event):
        action = "modified"
        if event.get("action").endswith("destroy"):
            action = "deleted"
        elif event.get("action").endswith("create"):
            action = "created"
        return f"web hook {action} in repository [{event.get('repo', '<UNKNOWN_REPO>')}]"

    def severity(self, event):
        if event.get("action").endswith("create"):
            return "MEDIUM"
        return "INFO"
