from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubOrgModified(Rule):
    id = "GitHub.Org.Modified-prototype"
    display_name = "GitHub User Added or Removed from Org"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_reference = "https://docs.github.com/en/organizations/managing-membership-in-your-organization"
    default_severity = Severity.INFO
    default_description = "Detects when a user is added or removed from a GitHub Org."

    def rule(self, event):
        return event.get("action") == "org.add_member" or event.get("action") == "org.remove_member"

    def title(self, event):
        action = event.get("action")
        if event.get("action") == "org.add_member":
            action = "added"
        elif event.get("action") == "org.remove_member":
            action = "removed"
        return f"GitHub.Audit: User [{event.udm('actor_user')}] {action} {event.get('user', '<UNKNOWN_USER>')} to org [{event.get('org', '<UNKNOWN_ORG>')}]"

    tests = [
        RuleTest(
            name="GitHub - Team Deleted",
            expected_result=False,
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
            name="GitHub - Org - User Added",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "org.add_member",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "user": "cat",
            },
        ),
        RuleTest(
            name="GitHub - Org - User Removed",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "org.remove_member",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "user": "bob",
            },
        ),
    ]
