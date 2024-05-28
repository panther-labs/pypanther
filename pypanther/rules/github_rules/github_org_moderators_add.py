from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import github_alert_context
from pypanther.log_types import LogType

git_hub_org_moderators_add_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Org Moderator Added",
        ExpectedResult=True,
        Log={
            "_document_id": "Ab123",
            "action": "organization_moderators.add_user",
            "actor": "sarah78",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-11 05:17:28.078",
            "created_at": "2022-12-11 05:17:28.078",
            "org": "example-io",
            "user": "john1987",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Org Moderator removed",
        ExpectedResult=False,
        Log={
            "_document_id": "Ab123",
            "action": "organization_moderators.remove_user",
            "actor": "sarah78",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-11 05:17:28.078",
            "created_at": "2022-12-11 05:17:28.078",
            "org": "example-io",
            "user": "john1987",
        },
    ),
]


class GitHubOrgModeratorsAdd(PantherRule):
    RuleID = "GitHub.Org.Moderators.Add-prototype"
    DisplayName = "GitHub User Added to Org Moderators"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    Severity = PantherSeverity.Medium
    Description = "Detects when a user is added to a GitHub org's list of moderators."
    Reference = "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-moderators-in-your-organization"
    Tests = git_hub_org_moderators_add_tests

    def rule(self, event):
        return event.get("action") == "organization_moderators.add_user"

    def title(self, event):
        return f"GitHub.Audit: User [{event.get('actor', '<UNKNOWN_ACTOR>')}] added user [{event.get('user', '<UNKNOWN_USER>')}] to moderators in [{event.get('org', '<UNKNOWN_ORG>')}]"

    def alert_context(self, event):
        return github_alert_context(event)
