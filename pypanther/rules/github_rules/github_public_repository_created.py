from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import github_alert_context
from pypanther.log_types import LogType

github_public_repository_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Public Repo Created",
        ExpectedResult=True,
        Log={
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
    PantherRuleTest(
        Name="Private Repo Created",
        ExpectedResult=False,
        Log={
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


class GithubPublicRepositoryCreated(PantherRule):
    Description = "A public Github repository was created."
    DisplayName = "Github Public Repository Created"
    Runbook = (
        "Confirm this github repository was intended to be created as 'public' versus 'private'."
    )
    Reference = "https://docs.github.com/en/get-started/quickstart/create-a-repo"
    Severity = PantherSeverity.Medium
    Tags = ["Github Repository", "Public", "Repository Created"]
    LogTypes = [LogType.GitHub_Audit]
    RuleID = "Github.Public.Repository.Created-prototype"
    SummaryAttributes = ["actor", "repository", "visibility"]
    Tests = github_public_repository_created_tests
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
