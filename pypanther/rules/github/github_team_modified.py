from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


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
        team_name = event.get("team") if "team" in event else "<MISSING_TEAM>"
        return f"GitHub.Audit: [{team_name}] has been modified"

    tests = [
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
