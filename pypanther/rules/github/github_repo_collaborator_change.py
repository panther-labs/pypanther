from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

github_repo_collaborator_change_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - Collaborator Added",
        expected_result=True,
        log={
            "actor": "bob",
            "action": "repo.add_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "cat",
        },
    ),
    RuleTest(
        name="GitHub - Collaborator Removed",
        expected_result=True,
        log={
            "actor": "bob",
            "action": "repo.remove_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
            "user": "cat",
        },
    ),
    RuleTest(
        name="GitHub - Non member action",
        expected_result=False,
        log={
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


@panther_managed
class GithubRepoCollaboratorChange(Rule):
    id = "Github.Repo.CollaboratorChange-prototype"
    display_name = "GitHub Repository Collaborator Change"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when a repository collaborator is added or removed."
    default_runbook = "Determine if the new collaborator is authorized to access the repository."
    default_reference = "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository"
    tests = github_repo_collaborator_change_tests

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
