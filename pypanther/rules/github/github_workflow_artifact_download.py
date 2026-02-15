from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubWebhookWorkflowArtifactDownload(Rule):
    id = "GitHub.Webhook.WorkflowArtifactDownload-prototype"
    display_name = "GitHub Workflow Downloading Artifacts"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0005:T1027"]}
    tags = ["CI/CD", "Workflow", "Artifacts"]
    create_alert = False
    default_severity = Severity.INFO
    default_description = "Detects when a GitHub Actions workflow downloads artifacts."
    default_reference = "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/#pwn-request-with-artifact-upload"

    def rule(self, event):
        if event.get("action") != "completed":
            return False
        steps = event.deep_get("workflow_job", "steps", default=[])
        # Look for artifact download in step names
        for step in steps:
            step_name = step.get("name", "").lower()
            if any(
                pattern in step_name
                for pattern in [
                    "download artifact",
                    "download-artifact",
                    "actions/download-artifact",
                    "restore artifact",
                    "get artifact",
                    "fetch artifact",
                    "pull artifact",
                ]
            ):
                return True
        return False

    def title(self, event):
        workflow_name = event.deep_get("workflow_job", "name", default="Unknown Workflow")
        repo_name = event.deep_get("repository", "full_name", default="Unknown Repository")
        return f"Artifact download detected in workflow '{workflow_name}' for {repo_name}"

    tests = [
        RuleTest(
            name="Workflow with artifact download",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003143,
                    "name": "Deploy",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345678,
                    "steps": [
                        {"name": "Setup", "status": "completed", "conclusion": "success"},
                        {"name": "Download artifact", "status": "completed", "conclusion": "success"},
                        {"name": "Deploy", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow with actions/download-artifact",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003144,
                    "name": "Process Build",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345679,
                    "steps": [
                        {"name": "Checkout", "status": "completed", "conclusion": "success"},
                        {"name": "actions/download-artifact@v4", "status": "completed", "conclusion": "success"},
                        {"name": "Process", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow with restore artifact step",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003145,
                    "name": "Test Results",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345680,
                    "steps": [
                        {"name": "Restore Artifact from Previous Run", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow without artifact download",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003146,
                    "name": "Build",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345681,
                    "steps": [
                        {"name": "Checkout", "status": "completed", "conclusion": "success"},
                        {"name": "Build", "status": "completed", "conclusion": "success"},
                        {"name": "Upload artifact", "status": "completed", "conclusion": "success"},
                    ],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Workflow job in progress",
            expected_result=False,
            log={
                "action": "in_progress",
                "workflow_job": {
                    "id": 52841003147,
                    "name": "Deploy",
                    "status": "in_progress",
                    "run_id": 12345682,
                    "steps": [{"name": "Download artifact", "status": "in_progress"}],
                },
                "repository": {"id": 123456789, "full_name": "example-org/example-repo"},
            },
        ),
    ]
