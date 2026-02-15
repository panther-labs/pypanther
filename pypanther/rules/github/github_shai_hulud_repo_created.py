from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_webhook_alert_context


@panther_managed
class GitHubWebhookSha1HuludRepoCreated(Rule):
    id = "GitHub.Webhook.Sha1HuludRepoCreated-prototype"
    display_name = "GitHub Sha1-Hulud Malicious Repository Created"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002"]}
    tags = ["GitHub", "Supply Chain", "Threat Intelligence"]
    default_severity = Severity.HIGH
    default_description = 'Detects when a repository is created with the description "Sha1-Hulud: The Second Coming.", which is a known indicator of compromise associated with the Sha1-Hulud 2.0 campaign.\n'
    default_runbook = "1. Immediately investigate the repository and its creator\n2. Review the repository owner's account for signs of compromise\n3. Check if any code has been pushed to the repository\n4. Review organization access and permissions for the user who created the repository\n5. Consider immediately archiving or deleting the repository\n6. Report the repository and user to GitHub Trust & Safety\n7. Review recent activity from the same user across all repositories\n8. Check for any downstream impacts if the repository was forked or cloned\n9. Notify security team and relevant stakeholders immediately\n"
    default_reference = "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security"

    def rule(self, event):
        if event.get("action") != "created":
            return False
        # Check if the repository description matches the Shai-Hulud indicator
        description = event.deep_get("repository", "description", default="")
        return description == "Sha1-Hulud: The Second Coming."

    def title(self, event):
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        user = event.deep_get("sender", "login", default="<UNKNOWN_USER>")
        return f"Sha1-Hulud malicious repository [{repo_name}] created by compromised user [{user}]"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        return context

    tests = [
        RuleTest(
            name="Sha1-Hulud Repository Created",
            expected_result=True,
            log={
                "action": "created",
                "repository": {
                    "id": 1104055056,
                    "node_id": "R_kgDOQc6LEA",
                    "name": "wuhhsdknjf",
                    "full_name": "Owner/wuhhsdknjf",
                    "private": True,
                    "owner": {"login": "Owner", "id": 123456789, "type": "Organization"},
                    "html_url": "https://github.com/Owner/wuhhsdknjf",
                    "description": "Sha1-Hulud: The Second Coming.",
                    "created_at": "2025-11-25T17:32:12Z",
                    "clone_url": "https://github.com/Owner/wuhhsdknjf.git",
                    "visibility": "private",
                },
                "organization": {"login": "Owner", "id": 123456789},
                "sender": {"login": "Owner", "id": 123456789, "type": "User", "html_url": "https://github.com/Owner"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal Repository Created",
            expected_result=False,
            log={
                "action": "created",
                "repository": {
                    "id": 123456789,
                    "name": "my-project",
                    "full_name": "myorg/my-project",
                    "private": False,
                    "owner": {"login": "myorg", "id": 987654321, "type": "Organization"},
                    "html_url": "https://github.com/myorg/my-project",
                    "description": "A legitimate project for data analysis",
                    "created_at": "2025-11-25T10:00:00Z",
                },
                "sender": {"login": "developer", "id": 111222333, "type": "User"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Different Event Action",
            expected_result=False,
            log={
                "action": "deleted",
                "repository": {
                    "id": 1104055056,
                    "name": "wuhhsdknjf",
                    "full_name": "Owner/wuhhsdknjf",
                    "description": "Sha1-Hulud: The Second Coming.",
                    "html_url": "https://github.com/Owner/wuhhsdknjf",
                },
                "sender": {"login": "giredeops", "id": 123456789, "type": "User"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
