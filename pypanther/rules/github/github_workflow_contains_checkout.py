from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubWebhookWorkflowContainsCheckout(Rule):
    id = "GitHub.Webhook.WorkflowContainsCheckout-prototype"
    display_name = "GitHub Workflow Contains Checkout Action"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072"]}
    tags = ["CI/CD", "Workflow", "Supply Chain"]
    default_severity = Severity.INFO
    create_alert = False
    default_description = "Detects when a GitHub Actions workflow job contains a checkout step. The checkout action (actions/checkout) pulls repository code into the workflow runner. In certain contexts, especially with pull_request_target triggers or workflows with elevated permissions, checking out untrusted code can pose security risks. This detection helps identify workflows that interact with repository code for security review.\n"
    default_reference = "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"

    def rule(self, event):
        """Alert when a GitHub workflow job contains a checkout action step."""
        # Only check completed workflow jobs
        if event.get("action") != "completed":
            return False
        # Get the steps array from workflow_job
        steps = event.deep_get("workflow_job", "steps", default=[])
        # Iterate through each step and check if the name contains "checkout" (case-insensitive)
        for step in steps:
            step_name = step.get("name", "").lower()
            if "checkout" in step_name:
                return True
        return False

    tests = [
        RuleTest(
            name="Workflow job with checkout step completed",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914522,
                    "name": "Validate PR Title",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/12345678/job/52841914522",
                    "head_branch": "feature-branch",
                    "head_sha": "abc123def456789",
                    "run_id": 12345678,
                    "runner_name": "GitHub Actions",
                    "started_at": "2025-10-15T18:41:58Z",
                    "completed_at": "2025-10-15T18:47:18Z",
                    "steps": [
                        {
                            "completed_at": "2025-10-15T18:42:00Z",
                            "conclusion": "success",
                            "name": "Set up job",
                            "number": 1,
                            "started_at": "2025-10-15T18:41:59Z",
                            "status": "completed",
                        },
                        {
                            "completed_at": "2025-10-15T18:42:02Z",
                            "conclusion": "success",
                            "name": "Checkout code",
                            "number": 2,
                            "started_at": "2025-10-15T18:42:00Z",
                            "status": "completed",
                        },
                        {
                            "completed_at": "2025-10-15T18:42:05Z",
                            "conclusion": "success",
                            "name": "Run tests",
                            "number": 3,
                            "started_at": "2025-10-15T18:42:02Z",
                            "status": "completed",
                        },
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo", "private": True},
            },
        ),
        RuleTest(
            name="Workflow job with case-insensitive checkout variation",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914523,
                    "name": "Build",
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [
                        {"name": "Setup environment", "status": "completed", "conclusion": "success"},
                        {"name": "CHECKOUT Repository", "status": "completed", "conclusion": "success"},
                        {"name": "Build project", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job with 'Post Checkout' step",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914524,
                    "name": "Deploy",
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [
                        {"name": "Initialize", "status": "completed", "conclusion": "success"},
                        {"name": "Post Checkout code", "status": "completed", "conclusion": "success"},
                        {"name": "Deploy application", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job without checkout step",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914525,
                    "name": "Lint",
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [
                        {"name": "Set up job", "status": "completed", "conclusion": "success"},
                        {"name": "Run linter", "status": "completed", "conclusion": "success"},
                        {"name": "Complete job", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job requested (not completed)",
            expected_result=False,
            log={
                "action": "requested",
                "workflow_job": {
                    "id": 52841914526,
                    "name": "Test",
                    "status": "queued",
                    "steps": [{"name": "Checkout code", "status": "pending"}],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job with empty steps array",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914527,
                    "name": "Empty Job",
                    "status": "completed",
                    "conclusion": "skipped",
                    "steps": [],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job with null steps",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841914528,
                    "name": "Null Steps Job",
                    "status": "completed",
                    "conclusion": "success",
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job in progress with checkout",
            expected_result=False,
            log={
                "action": "in_progress",
                "workflow_job": {
                    "id": 52841914529,
                    "name": "Build",
                    "status": "in_progress",
                    "steps": [
                        {"name": "Checkout code", "status": "completed", "conclusion": "success"},
                        {"name": "Build", "status": "in_progress"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
    ]
