from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubOrgModeratorsAdd(Rule):
    id = "GitHub.Org.Moderators.Add-prototype"
    display_name = "GitHub User Added to Org Moderators"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    default_severity = Severity.MEDIUM
    default_description = "Detects when a user is added to a GitHub org's list of moderators."
    default_reference = "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-moderators-in-your-organization"

    def rule(self, event):
        return event.get("action") == "organization_moderators.add_user"

    def title(self, event):
        return f"GitHub.Audit: User [{event.get('actor', '<UNKNOWN_ACTOR>')}] added user [{event.get('user', '<UNKNOWN_USER>')}] to moderators in [{event.get('org', '<UNKNOWN_ORG>')}]"

    def alert_context(self, event):
        return github_alert_context(event)

    tests = [
        RuleTest(
            name="GitHub - Org Moderator Added",
            expected_result=True,
            log={
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
        RuleTest(
            name="GitHub - Org Moderator removed",
            expected_result=False,
            log={
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
