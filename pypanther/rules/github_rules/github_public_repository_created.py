from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import github_alert_context

github_public_repository_created_tests: list[RuleTest] = [
    RuleTest(
        name="Public Repo Created",
        expected_result=True,
        log={
            "_document_id": "abCD",
            "action": "repo.create",
            "actor": "example-actor",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-11 22:40:20.268",
            "created_at": "2022-12-11 22:40:20.268",
            "org": "example-io",
            "repo": "example-io/oops",
            "visibility": "public",
        },
    ),
    RuleTest(
        name="Private Repo Created",
        expected_result=False,
        log={
            "_document_id": "abCD",
            "action": "repo.create",
            "actor": "example-actor",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-11 22:40:20.268",
            "created_at": "2022-12-11 22:40:20.268",
            "org": "example-io",
            "repo": "example-io/oops",
            "visibility": "private",
        },
    ),
]


@panther_managed
class GithubPublicRepositoryCreated(Rule):
    default_description = "A public Github repository was created."
    display_name = "Github Public Repository Created"
    default_runbook = "Confirm this github repository was intended to be created as 'public' versus 'private'."
    default_reference = "https://docs.github.com/en/get-started/quickstart/create-a-repo"
    default_severity = Severity.MEDIUM
    tags = ["Github Repository", "Public", "Repository Created"]
    log_types = [LogType.GITHUB_AUDIT]
    id = "Github.Public.Repository.Created-prototype"
    summary_attributes = ["actor", "repository", "visibility"]
    tests = github_public_repository_created_tests
    # def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # return ''

    def rule(self, event):
        # Return True if a public repository was created
        return event.get("action", "") == "repo.create" and event.get("visibility", "") == "public"

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created with public status by Github user [{event.get('actor')}]."

    def alert_context(self, event):
        #  (Optional) Return a dictionary with additional data to be included in the alert
        # sent to the SNS/SQS/Webhook destination
        return github_alert_context(event)
