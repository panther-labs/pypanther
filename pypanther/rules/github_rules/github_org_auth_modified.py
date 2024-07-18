from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_hub_org_auth_change_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - Authentication Method Changed",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "org.saml_disabled",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "org": "my-org",
            "repo": "my-org/my-repo",
        },
    ),
    RuleTest(
        name="GitHub - Non Auth Related Org Change",
        expected_result=False,
        log={
            "actor": "cat",
            "action": "invite_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


@panther_managed
class GitHubOrgAuthChange(Rule):
    id = "GitHub.Org.AuthChange-prototype"
    display_name = "GitHub Org Authentication Method Changed"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_severity = Severity.CRITICAL
    summary_attributes = ["actor", "action"]
    default_description = "Detects changes to GitHub org authentication changes."
    default_runbook = "Verify that the GitHub admin performed this activity and validate its use."
    default_reference = (
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github"
    )
    tests = git_hub_org_auth_change_tests
    AUTH_CHANGE_EVENTS = [
        "org.saml_disabled",
        "org.saml_enabled",
        "org.disable_two_factor_requirement",
        "org.enable_two_factor_requirement",
        "org.update_saml_provider_settings",
        "org.enable_oauth_app_restrictions",
        "org.disable_oauth_app_restrictions",
    ]

    def rule(self, event):
        if not event.get("action").startswith("org."):
            return False
        return event.get("action") in self.AUTH_CHANGE_EVENTS

    def title(self, event):
        return f"GitHub auth configuration was changed by {event.get('actor', '<UNKNOWN USER>')}"
