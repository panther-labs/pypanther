from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get
from pypanther.helpers.github import github_reference_url, github_webhook_alert_context, is_cross_fork_pr


@panther_managed
class GitHubWebhookPullRequestTargetUsage(Rule):
    id = "GitHub.Webhook.PullRequestTargetUsage-prototype"
    display_name = "GitHub pull_request_target Workflow Usage"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072", "TA0004:T1134"]}
    tags = ["CI/CD", "Workflow", "Privilege Escalation"]
    default_severity = Severity.HIGH
    default_description = "Detects usage of pull_request_target workflows, which run with elevated privileges and can access secrets even when triggered by external contributors from forks. These workflows pose security risks as they run in the context of the target repository rather than the fork, potentially allowing malicious code execution with write access and secrets. Low severity for non-cross-fork PRs.\n"
    default_runbook = "1. Verify the pull_request_target workflow is necessary and properly secured 2. Check that the workflow doesn't build or run untrusted code from the pull request 3. Ensure the workflow follows security best practices:\n   - Uses explicit checkout with trusted refs\n   - Validates inputs and doesn't execute arbitrary code\n   - Has minimal required permissions\n4. Review the workflow file for potential security vulnerabilities 5. Monitor for unusual activity from external contributors 6. Consider if pull_request event would be sufficient instead\n"
    default_reference = (
        "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target"
    )

    def rule(self, event):
        return event.deep_get("workflow_run", "event") == "pull_request_target"

    def title(self, event):
        workflow_name = event.deep_get("workflow_run", "name", default="<UNKNOWN_WORKFLOW>")
        repo_name = deep_get(event, "repository", "full_name", default="<UNKNOWN_REPO>")
        action = event.get("action", "<UNKNOWN_ACTION>")
        if is_cross_fork_pr(event):
            return (
                f"pull_request_target workflow [{workflow_name}] triggered by cross-fork PR in {repo_name} ({action})"
            )
        return f"pull_request_target workflow [{workflow_name}] triggered in {repo_name} ({action})"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        workflow_run = event.get("workflow_run", {})
        if workflow_run:
            context["workflow_run"] = {
                "id": workflow_run.get("id"),
                "name": workflow_run.get("name"),
                "event": workflow_run.get("event"),
                "status": workflow_run.get("status"),
                "conclusion": workflow_run.get("conclusion"),
                "html_url": workflow_run.get("html_url"),
            }
        return context

    def reference(self, event):
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    def severity(self, event):
        if is_cross_fork_pr(event):
            return "DEFAULT"
        return "LOW"

    tests = [
        RuleTest(
            name="Pull request target workflow completed",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_run": {
                    "id": 12345678,
                    "name": "Security Scan",
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/12345678",
                    "head_branch": "feature-branch",
                    "pull_requests": [
                        {
                            "number": 123,
                            "head": {
                                "ref": "feature-branch",
                                "repo": {
                                    "id": 243627255,
                                    "name": "example-repo",
                                    "full_name": "example-org/example-repo",
                                },
                            },
                            "base": {
                                "ref": "main",
                                "repo": {
                                    "id": 243627255,
                                    "name": "example-repo",
                                    "full_name": "example-org/example-repo",
                                },
                            },
                        },
                    ],
                },
                "repository": {"id": 243627255, "full_name": "example-org/example-repo", "private": True},
            },
        ),
        RuleTest(
            name="Cross-fork pull request target workflow",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_run": {
                    "id": 87654321,
                    "name": "Build and Test",
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "failure",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/87654321",
                    "head_branch": "malicious-feature",
                    "pull_requests": [
                        {
                            "number": 456,
                            "head": {
                                "ref": "malicious-feature",
                                "repo": {"id": 999999999, "name": "example-repo", "full_name": "attacker/example-repo"},
                            },
                            "base": {
                                "ref": "main",
                                "repo": {
                                    "id": 243627255,
                                    "name": "example-repo",
                                    "full_name": "example-org/example-repo",
                                },
                            },
                        },
                    ],
                },
                "repository": {"id": 243627255, "full_name": "example-org/example-repo", "private": False},
            },
        ),
        RuleTest(
            name="Regular pull request workflow (not target)",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_run": {
                    "id": 11111111,
                    "name": "CI Tests",
                    "event": "pull_request",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/11111111",
                    "head_branch": "safe-feature",
                    "pull_requests": [
                        {
                            "number": 789,
                            "head": {
                                "ref": "safe-feature",
                                "repo": {
                                    "id": 243627255,
                                    "name": "example-repo",
                                    "full_name": "example-org/example-repo",
                                },
                            },
                            "base": {
                                "ref": "main",
                                "repo": {
                                    "id": 243627255,
                                    "name": "example-repo",
                                    "full_name": "example-org/example-repo",
                                },
                            },
                        },
                    ],
                },
                "repository": {"id": 243627255, "full_name": "example-org/example-repo", "private": True},
            },
        ),
        RuleTest(
            name="Push workflow (not pull request related)",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_run": {
                    "id": 22222222,
                    "name": "Deploy",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/22222222",
                    "head_branch": "main",
                    "pull_requests": [],
                },
                "repository": {"id": 243627255, "full_name": "example-org/example-repo", "private": True},
            },
        ),
    ]
