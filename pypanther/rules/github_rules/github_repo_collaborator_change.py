from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

github_repo_collaborator_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Collaborator Added",
        ExpectedResult=True,
        Log={
            "actor": "bob",
            "action": "repo.add_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "cat",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Collaborator Removed",
        ExpectedResult=True,
        Log={
            "actor": "bob",
            "action": "repo.remove_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "cat",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Non member action",
        ExpectedResult=False,
        Log={
            "actor": "bob",
            "action": "repo.enable",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "cat",
        },
    ),
]


class GithubRepoCollaboratorChange(PantherRule):
    RuleID = "Github.Repo.CollaboratorChange-prototype"
    DisplayName = "GitHub Repository Collaborator Change"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    Severity = PantherSeverity.Medium
    Description = "Detects when a repository collaborator is added or removed."
    Runbook = "Determine if the new collaborator is authorized to access the repository."
    Reference = "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository"
    Tests = github_repo_collaborator_change_tests

    def rule(self, event):
        return event.get("action") in ("repo.add_member", "repo.remove_member")

    def title(self, event):
        repo_link = f"https://github.com/{event.get('repo', '<UNKNOWN_REPO>')}/settings/access"
        action = "added to"
        if event.get("action") == "repo.remove_member":
            action = "removed from"
        return f"Repository collaborator [{event.get('user', '<UNKNOWN_USER>')}] {action} repository {event.get('repo', '<UNKNOWN_REPO>')}. View current collaborators here: {repo_link}"

    def severity(self, event):
        if event.get("action") == "repo.remove_member":
            return "INFO"
        return "MEDIUM"
