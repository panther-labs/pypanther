import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubActionFailed(Rule):
    id = "GitHub.Action.Failed-prototype"
    display_name = "GitHub Action Failed"
    enabled = False
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Configuration Required"]
    default_severity = Severity.HIGH
    default_description = "A monitored github action has failed."
    default_runbook = "Inspect the action failure link and take appropriate response. There are no general plans of response for this activity.\n"
    default_reference = (
        "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes"
    )
    # The keys for MONITORED_ACTIONS are gh_org/repo_name
    # The values for MONITORED_ACTIONS are a list of ["action_names"]
    MONITORED_ACTIONS = {}

    def rule(self, event):
        if isinstance(self.MONITORED_ACTIONS, MagicMock):
            self.MONITORED_ACTIONS = json.loads(self.MONITORED_ACTIONS())  # pylint: disable=not-callable
        repo = event.get("repo", "")
        action_name = event.get("name", "")
        return all(
            [
                event.get("action", "") == "workflows.completed_workflow_run",
                event.get("conclusion", "") == "failure",
                repo in self.MONITORED_ACTIONS,
                action_name in self.MONITORED_ACTIONS.get(repo, []),
            ],
        )

    def title(self, event):
        repo = event.get("repo", "<NO_REPO>")
        action_name = event.get("name", "<NO_ACTION_NAME>")
        return f"GitHub Action [{action_name}] in [{repo}] has failed"

    def alert_context(self, event):
        a_c = github_alert_context(event)
        a_c["action"] = event.get("name", "<NO_ACTION_NAME>")
        a_c["action_run_link"] = (
            f"https://github.com/{a_c.get('repo')}/actions/runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
        )
        return a_c

    tests = [
        RuleTest(
            name="GitHub - Branch Protection Disabled",
            expected_result=False,
            log={
                "actor": "cat",
                "action": "protected_branch.destroy",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="GitHub Action Failed - No Configuration",
            expected_result=False,
            log={
                "_document_id": "pWWWWWWWWWWWWWWWWWWWWW",
                "action": "workflows.completed_workflow_run",
                "actor": "github_handle",
                "at_sign_timestamp": "2023-01-31 18:58:27.638",
                "business": "github-business-only-if-enterprise-audit-log",
                "completed_at": "2023-01-31T18:58:27.000Z",
                "conclusion": "failure",
                "created_at": "2023-01-31 18:58:27.638",
                "event": "schedule",
                "head_branch": "master",
                "head_sha": "66dddddddddddddddddddddddddddddddddddddd",
                "name": "sync-panther-analysis-from-upstream",
                "operation_type": "modify",
                "org": "panther-labs",
                "p_log_type": "GitHub.Audit",
                "public_repo": False,
                "repo": "your-org/panther-analysis-copy",
                "run_attempt": 3,
                "run_number": 99,
                "started_at": "2023-01-31 18:58:04",
                "workflow_id": 44444444,
                "workflow_run_id": 5555555555,
            },
        ),
        RuleTest(
            name="GitHub Action Failed - Monitored Action Configured",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="MONITORED_ACTIONS",
                    return_value='{\n  "your-org/panther-analysis-copy": [ "sync-panther-analysis-from-upstream"]\n}',
                ),
            ],
            log={
                "_document_id": "pWWWWWWWWWWWWWWWWWWWWW",
                "action": "workflows.completed_workflow_run",
                "actor": "github_handle",
                "at_sign_timestamp": "2023-01-31 18:58:27.638",
                "business": "github-business-only-if-enterprise-audit-log",
                "completed_at": "2023-01-31T18:58:27.000Z",
                "conclusion": "failure",
                "created_at": "2023-01-31 18:58:27.638",
                "event": "schedule",
                "head_branch": "master",
                "head_sha": "66dddddddddddddddddddddddddddddddddddddd",
                "name": "sync-panther-analysis-from-upstream",
                "operation_type": "modify",
                "org": "panther-labs",
                "p_log_type": "GitHub.Audit",
                "public_repo": False,
                "repo": "your-org/panther-analysis-copy",
                "run_attempt": 3,
                "run_number": 99,
                "started_at": "2023-01-31 18:58:04",
                "workflow_id": 44444444,
                "workflow_run_id": 5555555555,
            },
        ),
    ]
