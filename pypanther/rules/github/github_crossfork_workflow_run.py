from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get
from pypanther.helpers.github import is_cross_fork_pr


@panther_managed
class GitHubCrossForkWorkflowRun(Rule):
    id = "GitHub.CrossFork.Workflow.Run-prototype"
    display_name = "GitHub Cross-Fork Workflow Run"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072", "TA0004:T1134"]}
    tags = ["CI/CD", "Workflow"]
    create_alert = False
    default_severity = Severity.INFO
    default_description = "Tracks workflows run in cross-fork pull requests."
    default_reference = "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows"

    def rule(self, event):
        return (
            event.deep_get("workflow_run", "event") in ("pull_request_target", "pull_request")
            and event.get("action") == "requested"
            and (is_cross_fork_pr(event) is True)
        )

    def title(self, event):
        workflow_name = event.deep_get("workflow_run", "name", default="<UNKNOWN_WORKFLOW>")
        repo_name = deep_get(event, "repository", "full_name", default="<UNKNOWN_REPO>")
        action = event.get("action", "<UNKNOWN_ACTION>")
        title_str = f"Workflow [{workflow_name}] triggered by cross-fork PR in {repo_name} ({action})"
        return title_str

    tests = [
        RuleTest(
            name="Cross-fork pull request workflow",
            expected_result=True,
            log={
                "action": "requested",
                "workflow_run": {
                    "id": 87654321,
                    "name": "Build and Test",
                    "event": "pull_request",
                    "status": "in_progress",
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
            name="Cross-fork push workflow",
            expected_result=False,
            log={
                "action": "requested",
                "workflow_run": {
                    "id": 87654321,
                    "name": "Build and Test",
                    "event": "push",
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
            name="Not cross-fork",
            expected_result=False,
            log={
                "action": "requested",
                "workflow_run": {
                    "id": 18538851870,
                    "name": "Your-Workflow",
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "failure",
                    "html_url": "https://github.com/example-org/example-repo/actions/runs/18538851870",
                    "head_branch": "deathcon",
                    "pull_requests": [],
                    "head_repository": {"id": 1072340117, "full_name": "example-org/example-repo", "fork": False},
                    "repository": {"id": 1072340117, "full_name": "example-org/example-repo"},
                },
                "repository": {"id": 1072340117, "full_name": "example-org/example-repo", "private": True},
            },
        ),
    ]
