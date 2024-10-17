from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GithubOrganizationAppIntegrationInstalled(Rule):
    default_description = "An application integration was installed to your organization's Github account by someone in your organization."
    display_name = "Github Organization App Integration Installed"
    default_reference = (
        "https://docs.github.com/en/enterprise-server@3.4/developers/apps/managing-github-apps/installing-github-apps"
    )
    default_runbook = "Confirm that the app integration installation was a desired behavior."
    default_severity = Severity.LOW
    tags = ["Application Installation", "Github"]
    log_types = [LogType.GITHUB_AUDIT]
    id = "Github.Organization.App.Integration.Installed-prototype"
    summary_attributes = ["actor", "name"]
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

    tests = [
        RuleTest(
            name="App Integration Installation",
            expected_result=True,
            log={
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
        RuleTest(
            name="App Integration Installation-2",
            expected_result=True,
            log={
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
        RuleTest(
            name="Repository Archived",
            expected_result=False,
            log={
                "action": "repo.archived",
                "actor": "cat",
                "created_at": 1621305118553.0,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
            },
        ),
    ]
