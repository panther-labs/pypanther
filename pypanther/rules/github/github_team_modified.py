from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_hub_team_modified_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - Team Deleted",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "team.destroy",
            "created_at": 1621305118553,
            "data": {"team": "my-org/my-team"},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Team Created",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "team.create",
            "created_at": 1621305118553,
            "data": {"team": "my-org/my-team"},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Team Add repository",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "team.add_repository",
            "created_at": 1621305118553,
            "data": {"team": "my-org/my-team"},
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


@panther_managed
class GitHubTeamModified(Rule):
    id = "GitHub.Team.Modified-prototype"
    display_name = "GitHub Team Modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_reference = "https://docs.github.com/en/organizations/organizing-members-into-teams"
    default_severity = Severity.INFO
    default_description = "Detects when a team is modified in some way, such as adding a new team, deleting a team, modifying members, or a change in repository control."
    tests = git_hub_team_modified_tests

    def rule(self, event):
        if not event.get("action").startswith("team"):
            return False
        return (
            event.get("action") == "team.add_member"
            or event.get("action") == "team.add_repository"
            or event.get("action") == "team.change_parent_team"
            or (event.get("action") == "team.create")
            or (event.get("action") == "team.destroy")
            or (event.get("action") == "team.remove_member")
            or (event.get("action") == "team.remove_repository")
        )

    def title(self, event):
        action_mappings = {
            "create": "created team",
            "destroy": "deleted team",
            "add_member": f"added member [{event.get('user')}] to team",
            "remove_member": f"removed member [{event.get('user')}] from team",
            "add_repository": f"added repository [{event.get('repo')}] to team",
            "removed_repository": f"removed repository [{event.get('repo')}] from team",
            "change_parent_team": "changed parent team for team",
        }
        action_key = event.get("action").split(".")[1]
        action = action_mappings.get(action_key, event.get("action"))
        team_name = event.get("team") if "team" in event else "<MISSING_TEAM>"
        return f"GitHub.Audit: User [{event.udm('actor_user')}] {action} [{team_name}]"
