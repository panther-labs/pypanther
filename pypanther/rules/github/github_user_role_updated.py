from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubUserRoleUpdated(Rule):
    id = "GitHub.User.RoleUpdated-prototype"
    display_name = "GitHub User Role Updated"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_reference = "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization"
    default_severity = Severity.HIGH
    default_description = "Detects when a GitHub user role is upgraded to an admin or downgraded to a member"

    def rule(self, event):
        return event.get("action") == "org.update_member"

    def title(self, event):
        return f"Org owner [{event.udm('actor_user')}] updated user's [{event.get('user')}] role ('admin' or 'member')"

    tests = [
        RuleTest(
            name="GitHub - Member Updated",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "org.update_member",
                "created_at": 1621305118553,
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
                "user": "bob",
            },
        ),
        RuleTest(
            name="GitHub - Member Invited",
            expected_result=False,
            log={
                "actor": "cat",
                "action": "org.invite_member",
                "created_at": 1621305118553,
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
                "user": "bob",
            },
        ),
    ]
