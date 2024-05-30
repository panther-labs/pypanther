import json
from typing import List
from unittest.mock import MagicMock

from pypanther.base import PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get, github_alert_context
from pypanther.log_types import LogType

git_hub_action_failed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Branch Protection Disabled",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "protected_branch.destroy",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub Action Failed - No Configuration",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="GitHub Action Failed - Monitored Action Configured",
        ExpectedResult=True,
        Mocks=[
            PantherRuleMock(
                ObjectName="MONITORED_ACTIONS",
                ReturnValue='{\n  "your-org/panther-analysis-copy": [ "sync-panther-analysis-from-upstream"]\n}',
            )
        ],
        Log={
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


class GitHubActionFailed(PantherRule):
    RuleID = "GitHub.Action.Failed-prototype"
    DisplayName = "GitHub Action Failed"
    Enabled = False
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Configuration Required"]
    Severity = PantherSeverity.High
    Description = "A monitored github action has failed."
    Runbook = "Inspect the action failure link and take appropriate response. There are no general plans of response for this activity.\n"
    Reference = "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes"
    Tests = git_hub_action_failed_tests
    # The keys for MONITORED_ACTIONS are gh_org/repo_name
    # The values for MONITORED_ACTIONS are a list of ["action_names"]
    MONITORED_ACTIONS = {}

    def rule(self, event):
        if isinstance(self.MONITORED_ACTIONS, MagicMock):
            self.MONITORED_ACTIONS = json.loads(
                self.MONITORED_ACTIONS()
            )  # pylint: disable=not-callable
        repo = deep_get(event, "repo", default="")
        action_name = deep_get(event, "name", default="")
        return all(
            [
                deep_get(event, "action", default="") == "workflows.completed_workflow_run",
                repo in self.MONITORED_ACTIONS,
                action_name in self.MONITORED_ACTIONS.get(repo, []),
                deep_get(event, "conclusion", default="") == "failure",
            ]
        )

    def title(self, event):
        repo = deep_get(event, "repo", default="<NO_REPO>")
        action_name = deep_get(event, "name", default="<NO_ACTION_NAME>")
        return f"The GitHub Action [{action_name}] in [{repo}] has failed"

    def alert_context(self, event):
        a_c = github_alert_context(event)
        a_c["action"] = event.get("name", "<NO_ACTION_NAME>")
        a_c["action_run_link"] = (
            f"https://github.com/{a_c.get('repo')}/actions/runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
        )
        return a_c
