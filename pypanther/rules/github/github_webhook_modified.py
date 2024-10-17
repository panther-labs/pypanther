from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubWebhookModified(Rule):
    id = "GitHub.Webhook.Modified-prototype"
    display_name = "GitHub Web Hook Modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Exfiltration:Automated Exfiltration"]
    reports = {"MITRE ATT&CK": ["TA0010:T1020"]}
    default_reference = "https://docs.github.com/en/webhooks/about-webhooks"
    default_severity = Severity.INFO
    default_description = "Detects when a webhook is added, modified, or deleted"

    def rule(self, event):
        return event.get("action").startswith("hook.")

    def title(self, event):
        repo = event.get("repo", "<UNKNOWN_REPO>")
        action = "modified"
        if event.get("action").endswith("destroy"):
            action = "deleted"
        elif event.get("action").endswith("create"):
            action = "created"
        title_str = f"Github webhook [{event.deep_get('config', 'url', default='<UNKNOWN_URL>')}] {action} by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        if repo != "<UNKNOWN_REPO>":
            title_str += f" in repository [{repo}]"
        return title_str

    def severity(self, event):
        if event.get("action").endswith("create"):
            return "MEDIUM"
        return "INFO"

    def alert_context(self, event):
        ctx = github_alert_context(event)
        ctx["business"] = event.get("business", "")
        ctx["hook_id"] = event.get("hook_id", "")
        ctx["integration"] = event.get("integration", "")
        ctx["operation_type"] = event.get("operation_type", "")
        ctx["url"] = event.deep_get("config", "url", default="<UNKNOWN_URL>")
        return ctx

    tests = [
        RuleTest(
            name="GitHub - Webhook Created",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "hook.create",
                "data": {
                    "hook_id": 111222333444555,
                    "events": ["fork", "public", "pull_request", "push", "repository"],
                },
                "config": {"url": "https://fake.url"},
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
                "public_repo": False,
            },
        ),
        RuleTest(
            name="GitHub - Webhook Deleted",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "hook.destroy",
                "data": {
                    "hook_id": 111222333444555,
                    "events": ["fork", "public", "pull_request", "push", "repository"],
                },
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
                "public_repo": False,
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
                "repo": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="Github - App Webhook Created",
            expected_result=True,
            log={
                "action": "hook.create",
                "actor": "dog",
                "actor_id": "11112222",
                "actor_location": {"country_code": "US"},
                "business": "my-biz",
                "business_id": "9999999",
                "config": {"content_type": "json", "insecure_ssl": "0", "url": "https://fake.url/"},
                "hook_id": "111222333444555",
                "integration": "My Cool Github Integration",
                "name": "webhook",
                "operation_type": "create",
                "org": "my-org",
                "org_id": 9999999,
                "p_log_type": "GitHub.Audit",
            },
        ),
    ]
