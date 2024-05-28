from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_repo_hook_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Webhook Created",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "hook.create",
            "data": {
                "hook_id": 111222333444555,
                "events": ["fork", "public", "pull_request", "push", "repository"],
            },
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Webhook Deleted",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "hook.destroy",
            "data": {
                "hook_id": 111222333444555,
                "events": ["fork", "public", "pull_request", "push", "repository"],
            },
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Non Webhook Event",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "org.invite_member",
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repository": "my-org/my-repo",
        },
    ),
]


class GitHubRepoHookModified(PantherRule):
    RuleID = "GitHub.Repo.HookModified-prototype"
    DisplayName = "GitHub Web Hook Modified"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Exfiltration:Automated Exfiltration"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1020"]}
    Reference = "https://docs.github.com/en/webhooks/about-webhooks"
    Severity = PantherSeverity.Info
    Description = "Detects when a web hook is added, modified, or deleted in an org repository."
    Tests = git_hub_repo_hook_modified_tests

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
