from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_org_auth_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Authentication Method Changed",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "org.saml_disabled",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "org": "my-org",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Non Auth Related Org Change",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "invite_member",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GitHubOrgAuthChange(PantherRule):
    RuleID = "GitHub.Org.AuthChange-prototype"
    DisplayName = "GitHub Org Authentication Method Changed"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Persistence:Account Manipulation"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Severity = PantherSeverity.Critical
    SummaryAttributes = ["actor", "action"]
    Description = "Detects changes to GitHub org authentication changes."
    Runbook = "Verify that the GitHub admin performed this activity and validate its use."
    Reference = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github"
    Tests = git_hub_org_auth_change_tests
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
