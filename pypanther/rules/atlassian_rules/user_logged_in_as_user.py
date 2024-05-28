from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

atlassian_user_logged_in_as_user_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Admin impersonated user successfully",
        ExpectedResult=True,
        Log={
            "attributes": {
                "action": "user_logged_in_as_user",
                "actor": {
                    "email": "example.admin@example.com",
                    "id": "1234567890abcdefghijklmn",
                    "name": "Example Admin",
                },
                "container": [
                    {
                        "attributes": {
                            "siteHostName": "https://example.atlassian.net",
                            "siteName": "example",
                        },
                        "id": "12345678-abcd-9012-efgh-1234567890abcd",
                        "links": {"alt": "https://example.atlassian.net"},
                        "type": "sites",
                    }
                ],
                "context": [
                    {
                        "attributes": {
                            "accountType": "atlassian",
                            "email": "example.user@example.io",
                            "name": "example.user@example.io",
                        },
                        "type": "users",
                    }
                ],
                "time": "2022-12-15T00:35:15.890Z",
            },
            "id": "2508d209-3336-4763-89a0-aceaf1322fcf",
            "message": {"content": "Logged in as example.user@example.io", "format": "simple"},
        },
    ),
    PantherRuleTest(
        Name="user_logged_in_as_user not in log",
        ExpectedResult=False,
        Log={
            "attributes": {
                "action": "user_login",
                "actor": {
                    "email": "example.admin@example.com",
                    "id": "1234567890abcdefghijklmn",
                    "name": "Example Admin",
                },
                "container": [
                    {
                        "attributes": {
                            "siteHostName": "https://example.atlassian.net",
                            "siteName": "example",
                        },
                        "id": "12345678-abcd-9012-efgh-1234567890abcd",
                        "links": {"alt": "https://example.atlassian.net"},
                        "type": "sites",
                    }
                ],
                "context": [
                    {
                        "attributes": {
                            "accountType": "atlassian",
                            "email": "example.user@example.io",
                            "name": "example.user@example.io",
                        },
                        "type": "users",
                    }
                ],
                "time": "2022-12-15T00:35:15.890Z",
            },
            "id": "2508d209-3336-4763-89a0-aceaf1322fcf",
            "message": {"content": "Logged in as example.user@example.io", "format": "simple"},
        },
    ),
]


class AtlassianUserLoggedInAsUser(PantherRule):
    DisplayName = "Atlassian admin impersonated another user"
    RuleID = "Atlassian.User.LoggedInAsUser-prototype"
    Severity = PantherSeverity.High
    LogTypes = [LogType.Atlassian_Audit]
    Tags = ["Atlassian", "User impersonation"]
    Description = "Reports when an Atlassian user logs in (impersonates) another user.\n"
    Runbook = "Validate that the Atlassian admin did log in (impersonate) as another user.\n"
    Reference = "https://support.atlassian.com/user-management/docs/log-in-as-another-user/"
    Tests = atlassian_user_logged_in_as_user_tests

    def rule(self, event):
        return (
            deep_get(event, "attributes", "action", default="<unknown-action>")
            == "user_logged_in_as_user"
        )

    def title(self, event):
        actor = deep_get(event, "attributes", "actor", "email", default="<unknown-email>")
        context = deep_get(event, "attributes", "context", default=[{}])
        impersonated_user = context[0].get("attributes", {}).get("email", "<unknown-email>")
        return f"{actor} logged in as {impersonated_user}."

    def alert_context(self, event):
        return {
            "Timestamp": deep_get(event, "attributes", "time", default="<unknown-time>"),
            "Actor": deep_get(
                event, "attributes", "actor", "email", default="<unknown-actor-email>"
            ),
            "Impersonated user": deep_get(event, "attributes", "context", default=[{}])[0]
            .get("attributes", {})
            .get("email", "<unknown-email>"),
            "Event ID": event.get("id"),
        }
