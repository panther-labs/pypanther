from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubWebhookSelfHostedRunnerUsed(Rule):
    id = "GitHub.Webhook.SelfHostedRunnerUsed-prototype"
    display_name = "GitHub Workflow Using Self-Hosted Runner"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072", "TA0008:T1021"]}
    tags = ["CI/CD", "Workflow", "Self-Hosted", "Infrastructure"]
    create_alert = False
    default_severity = Severity.INFO
    default_description = "Detects when a GitHub Actions workflow runs on a self-hosted runner."
    default_reference = "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"

    def rule(self, event):
        # Only check completed workflow jobs
        if event.get("action") != "completed":
            return False
        # GitHub-hosted runners always have "GitHub Actions" in the runner_name
        # Self-hosted runners cannot use this reserved name
        runner_name = event.deep_get("workflow_job", "runner_name", default="")
        # Must have a runner name and it must not be GitHub-hosted
        if not runner_name:
            return False
        return not runner_name.startswith("GitHub Actions")

    def title(self, event):
        workflow_name = event.deep_get("workflow_job", "name", default="Unknown Workflow")
        repo_name = event.deep_get("repository", "full_name", default="Unknown Repository")
        runner_name = event.deep_get("workflow_job", "runner_name", default="Unknown Runner")
        return f"Self-hosted runner '{runner_name}' used in workflow '{workflow_name}' for {repo_name}"

    def alert_context(self, event):
        workflow_job = event.get("workflow_job", {})
        repository = event.get("repository", {})
        return {
            "workflow_name": workflow_job.get("name"),
            "workflow_job_id": workflow_job.get("id"),
            "workflow_run_id": workflow_job.get("run_id"),
            "workflow_url": workflow_job.get("html_url"),
            "repository": repository.get("full_name"),
            "repository_private": repository.get("private"),
            "repository_visibility": repository.get("visibility"),
            "head_branch": workflow_job.get("head_branch"),
            "head_sha": workflow_job.get("head_sha"),
            "conclusion": workflow_job.get("conclusion"),
            "runner_name": workflow_job.get("runner_name"),
            "runner_group_name": workflow_job.get("runner_group_name"),
            "runner_id": workflow_job.get("runner_id"),
            "runner_group_id": workflow_job.get("runner_group_id"),
            "actor": event.deep_get("sender", "login"),
        }

    def severity(self, event):
        # Public or forkable repos with self-hosted runners have a medium risk
        repo_visibility = event.deep_get("repository", "visibility")
        allow_forking = event.deep_get("repository", "allow_forking", default=False)
        is_private = event.deep_get("repository", "private", default=True)
        if repo_visibility == "public" or not is_private or allow_forking:
            return "MEDIUM"
        # Private, non-forkable repos are low risk
        return "INFO"

    tests = [
        RuleTest(
            name="Self-hosted runner on public repository",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003143,
                    "name": "Build",
                    "status": "completed",
                    "conclusion": "success",
                    "run_url": "https://github.com/example-org/example-repo/actions/runs/12345678/job/52841003143",
                    "head_branch": "main",
                    "head_sha": "abc123",
                    "run_id": 12345678,
                    "runner_group_id": 1,
                    "runner_group_name": "Default",
                    "runner_id": 42,
                    "runner_name": "my-runner-01",
                    "started_at": "2025-10-15T18:31:06Z",
                    "completed_at": "2025-10-15T18:41:54Z",
                    "steps": [{"name": "Setup", "status": "completed", "conclusion": "success"}],
                },
                "repository": {
                    "id": 123456789,
                    "full_name": "example-org/example-repo",
                    "private": False,
                    "visibility": "public",
                    "allow_forking": True,
                },
                "sender": {"login": "developer"},
            },
        ),
        RuleTest(
            name="Self-hosted runner on private forkable repository",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003144,
                    "name": "Deploy",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345679,
                    "runner_group_id": 2,
                    "runner_group_name": "Production",
                    "runner_id": 43,
                    "runner_name": "prod-runner-vm-02",
                },
                "repository": {
                    "id": 123456790,
                    "full_name": "example-org/private-repo",
                    "private": True,
                    "visibility": "private",
                    "allow_forking": True,
                },
                "sender": {"login": "developer"},
            },
        ),
        RuleTest(
            name="Self-hosted runner on private non-forkable repository",
            expected_result=True,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003145,
                    "name": "Test",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345680,
                    "runner_group_id": 1,
                    "runner_group_name": "Default",
                    "runner_id": 44,
                    "runner_name": "internal-runner",
                },
                "repository": {
                    "id": 123456791,
                    "full_name": "example-org/internal-repo",
                    "private": True,
                    "visibility": "private",
                    "allow_forking": False,
                },
                "sender": {"login": "developer"},
            },
        ),
        RuleTest(
            name="GitHub-hosted runner (not self-hosted)",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {
                    "id": 52841003146,
                    "name": "Lint",
                    "status": "completed",
                    "conclusion": "success",
                    "run_id": 12345681,
                    "runner_group_id": 0,
                    "runner_group_name": "GitHub Actions",
                    "runner_id": 1000000001,
                    "runner_name": "GitHub Actions 1000000001",
                },
                "repository": {"id": 123456792, "full_name": "example-org/example-repo", "private": True},
            },
        ),
        RuleTest(
            name="Workflow job in progress (not completed)",
            expected_result=False,
            log={
                "action": "in_progress",
                "workflow_job": {
                    "id": 52841003147,
                    "name": "Build",
                    "status": "in_progress",
                    "run_id": 12345682,
                    "runner_name": "my-runner-01",
                },
                "repository": {"id": 123456793, "full_name": "example-org/example-repo"},
            },
        ),
        RuleTest(
            name="Self-hosted runner with empty name",
            expected_result=False,
            log={
                "action": "completed",
                "workflow_job": {"id": 52841003148, "status": "completed", "run_id": 12345683, "runner_name": ""},
                "repository": {"id": 123456794, "full_name": "example-org/example-repo"},
            },
        ),
    ]
