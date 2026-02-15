from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubWorkflowDispatchByGitHubBot(Rule):
    id = "GitHub.Workflow.DispatchByGitHubBot-prototype"
    display_name = "GitHub Workflow Dispatched by GitHub Actions Bot"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub"]
    status = "Experimental"
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = Severity.INFO
    default_description = "Detects when a GitHub App server-to-server token (GITHUB_TOKEN) triggers a workflow manually through the workflow_dispatch event, creating a new workflow run. This activity may indicate that a possibly previously exfiltrated GITHUB_TOKEN was subsequently used to authenticate to the GitHub REST API to trigger a workflow manually.  This technique has been observed as the last step in the attack chain of the Nx/S1ngularity supply chain attack.\n"
    default_runbook = "1. Identify the workflow and repository:\n   - Review the workflow name and repository from the alert details\n   - Check the workflow_run_link in the alert context to view the workflow run details\n2. Review the workflow contents:\n   - Examine the workflow file (.github/workflows/) for potentially malicious actions\n   - Check for suspicious steps like secret exfiltration or unauthorized deployments\n   - Verify the workflow or any scripts used in the workflow itself haven't been recently modified in an unauthorized manner\n3. If suspicious or unauthorized:\n   - Immediately cancel the workflow run if it's still in progress\n   - Review GitHub audit logs for other activities by this token_id\n   - Rotate any secrets that may have been exposed to this workflow\n   - Review all recent workflow modifications and runs\n"
    default_reference = "https://nx.dev/blog/s1ngularity-postmortem"

    def rule(self, event):
        return all(
            [
                event.get("programmatic_access_type") == "GitHub App server-to-server token",
                event.get("event") == "workflow_dispatch",
                event.get("actor") == "github-actions[bot]",
                event.get("action") == "workflows.created_workflow_run",
            ],
        )

    def title(self, event):
        repo = event.get("repo", default="<NO_REPO>")
        workflow_name = event.get("name", default="<NO_WORKFLOW_NAME>")
        user = event.get("actor")
        return f"Bot [{user}] manually triggered a workflow dispatch for [{workflow_name}] in [{repo}]"

    def alert_context(self, event):
        context = github_alert_context(event)
        context["workflow_name"] = event.get("name", "<NO_WORKFLOW_NAME>")
        context["workflow_id"] = event.get("workflow_id")
        context["workflow_run_id"] = event.get("workflow_run_id")
        context["head_branch"] = event.get("head_branch")
        context["head_sha"] = event.get("head_sha")
        context["programmatic_access_type"] = event.get("programmatic_access_type")
        context["token_id"] = event.get("token_id")
        context["workflow_run_link"] = (
            f"https://github.com/{context.get('repo')}/actions/runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
        )
        return context

    tests = [
        RuleTest(
            name="GitHub App Manual Workflow Dispatch by Bot",
            expected_result=True,
            log={
                "action": "workflows.created_workflow_run",
                "actor": "github-actions[bot]",
                "actor_id": "12345678",
                "actor_is_agent": False,
                "actor_is_bot": True,
                "at_sign_timestamp": "2025-10-15 18:45:47.048000000",
                "business": "yourcompany",
                "business_id": "485638",
                "created_at": "2025-10-15 18:45:47.048000000",
                "event": "workflow_dispatch",
                "head_branch": "bot-branch",
                "name": "Your Workflow",
                "operation_type": "create",
                "org": "YourCompany",
                "org_id": 12345678,
                "programmatic_access_type": "GitHub App server-to-server token",
                "repo": "YourCompany/YourRepo",
                "repo_id": 12345678,
                "run_number": 1,
                "started_at": "2025-10-15 18:45:47.000000000",
                "token_id": "1111111111111",
                "user_agent": "launch/production",
                "workflow_id": "123456789",
                "workflow_run_id": "123456789",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "p_event_time": "2025-10-15 18:45:47.048000000",
                "p_log_type": "GitHub.Audit",
                "action": "workflows.created_workflow_run",
                "actor": "github-actions[bot]",
                "actor_id": "123456789",
                "event": "push",
                "programmatic_access_type": "GitHub App server-to-server token",
                "repo": "YourCompany/YourRepo",
                "workflow_id": "123456789",
            },
        ),
    ]
