from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import github_alert_context
from pypanther.log_types import LogType

github_organization_app_integration_installed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="App Integration Installation",
        ExpectedResult=True,
        Log={
            "_document_id": "A-2345",
            "action": "integration_installation.create",
            "actor": "user_name",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-11 05:28:05.542",
            "created_at": "2022-12-11 05:28:05.542",
            "name": "Microsoft Teams for GitHub",
            "org": "your-organization",
            "p_any_usernames": ["user_name"],
        },
    ),
    PantherRuleTest(
        Name="App Integration Installation-2",
        ExpectedResult=True,
        Log={
            "_document_id": "A-1234",
            "action": "integration_installation.create",
            "actor": "leetboy",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-02 17:40:08.671",
            "created_at": "2022-12-02 17:40:08.671",
            "name": "Datadog CI",
            "org": "example-io",
        },
    ),
    PantherRuleTest(
        Name="Repository Archived",
        ExpectedResult=False,
        Log={
            "action": "repo.archived",
            "actor": "cat",
            "created_at": 1621305118553.0,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GithubOrganizationAppIntegrationInstalled(PantherRule):
    Description = "An application integration was installed to your organization's Github account by someone in your organization."
    DisplayName = "Github Organization App Integration Installed"
    Reference = "https://docs.github.com/en/enterprise-server@3.4/developers/apps/managing-github-apps/installing-github-apps"
    Runbook = "Confirm that the app integration installation was a desired behavior."
    Severity = PantherSeverity.Low
    Tags = ["Application Installation", "Github"]
    LogTypes = [LogType.GitHub_Audit]
    RuleID = "Github.Organization.App.Integration.Installed-prototype"
    SummaryAttributes = ["actor", "name"]
    Tests = github_organization_app_integration_installed_tests
    # def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # return ''

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        # Creates a new alert if the event's action was ""
        return event.get("action") == "integration_installation.create"

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        return f" Github User [{event.get('actor', {})}] in [{event.get('org')}] installed the following integration: [{event.get('name')}]."

    def alert_context(self, event):
        #  (Optional) Return a dictionary with additional data to be included in the
        #  alert sent to the SNS/SQS/Webhook destination
        return github_alert_context(event)
