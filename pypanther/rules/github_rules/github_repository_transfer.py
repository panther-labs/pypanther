from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import github_alert_context

github_repository_transfer_tests: list[RuleTest] = [
    RuleTest(
        name="Public Repo Created",
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
            "visibility": "public",
        },
    ),
    RuleTest(
        name="Repo Transfer Outgoing",
        expected_result=True,
        log={
            "_document_id": "BodJtQIrT3kWMIQpm1ANew",
            "action": "repo.transfer_outgoing",
            "actor": "user-name",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-14 19:16:31.299",
            "created_at": "2022-12-14 19:16:31.299",
            "org": "your-organization",
            "repo": "your-organizatoin/project_repo",
            "visibility": "private",
        },
    ),
    RuleTest(
        name="Repo Transfer Start",
        expected_result=True,
        log={
            "_document_id": "BodJtQIrT3kWMIQpm1ANew",
            "action": "repo.transfer_start",
            "actor": "user-name",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-14 19:16:31.299",
            "created_at": "2022-12-14 19:16:31.299",
            "org": "your-organization",
            "repo": "your-organizatoin/project_repo",
            "visibility": "private",
        },
    ),
    RuleTest(
        name="Repository Transfer",
        expected_result=True,
        log={
            "_document_id": "CFyS8UJsQjJfCgsmTLI6mQ",
            "action": "repo.transfer",
            "actor": "org-user",
            "actor_location": {"country_code": "US"},
            "at_sign_timestamp": "2022-12-14 19:21:01.035",
            "created_at": "2022-12-14 19:21:01.035",
            "org": "your-organization",
            "repo": "your-organization/project_repo",
            "visibility": "private",
        },
    ),
]


@panther_managed
class GithubRepositoryTransfer(Rule):
    default_description = "A user accepted a request to receive a transferred Github repository, a  Github repository was transferred to another repository network, or a user sent a request to transfer a repository to another user or organization."
    display_name = "Github Repository Transfer"
    default_reference = "https://docs.github.com/en/enterprise-server@3.3/repositories/creating-and-managing-repositories/transferring-a-repository\n\nhttps://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#repo-category-actions"
    default_runbook = "Please check with the referenced users or their supervisors to ensure the transferring of this repository is expected and allowed."
    default_severity = Severity.MEDIUM
    tags = ["Github Repository", "Github Repository Transfer", "Repository", "Transfer"]
    log_types = [LogType.GITHUB_AUDIT]
    id = "Github.Repository.Transfer-prototype"
    summary_attributes = ["action"]
    tests = github_repository_transfer_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") in ("repo.transfer", "repo.transfer_outgoing", "repo.transfer_start")

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        action = event.get("action", "")
        if action == "repo.transfer":
            # return something like: A user accepted a request to receive a transferred repository.
            return f"Github User [{event.get('actor', 'NO_ACTOR_FOUND')}] accepted a request to receive repository [{event.get('repo', 'NO_REPO_NAME_FOUND')}] in [{event.get('org', 'NO_ORG_NAME_FOUND')}]."
        if action == "repo.transfer_outgoing":
            # return something like: A repository was transferred to another repository network.
            return f"Github User [{event.get('actor', 'NO_ACTOR_FOUND')}] transferred repository [{event.get('repo', 'NO_REPO_NAME_FOUND')}] in [{event.get('org', 'NO_ORG_NAME_FOUND')}]."
        if action == "repo.transfer_start":
            # return something like: A user sent a request to transfer a
            # repository to another user or organization.
            return f"Github User [{event.get('actor', 'NO_ACTOR_FOUND')}] sent a request to transfer repository [{event.get('repo', 'NO_REPO_NAME_FOUND')}] to another user or organization."
        return ""

    def alert_context(self, event):
        #  (Optional) Return a dictionary with additional data to be included in the alert
        # sent to the SNS/SQS/Webhook destination
        return github_alert_context(event)
