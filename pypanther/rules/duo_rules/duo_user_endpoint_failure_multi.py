from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

duo_user_endpoint_failure_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="endpoint_is_not_in_management_system",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "endpoint_is_not_in_management_system",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="endpoint_failed_google_verification",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "endpoint_failed_google_verification",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="endpoint_is_not_trusted",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "endpoint_is_not_trusted",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="could_not_determine_if_endpoint_was_trusted",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "could_not_determine_if_endpoint_was_trusted",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="invalid_device",
        ExpectedResult=True,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "invalid_device",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="good_auth",
        ExpectedResult=False,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_approved",
            "result": "success",
            "user": {"name": "example@example.io"},
        },
    ),
    PantherRuleTest(
        Name="denied_old_creds",
        ExpectedResult=False,
        Log={
            "access_device": {"ip": "12.12.112.25", "os": "Mac OS X"},
            "auth_device": {"ip": "12.12.12.12"},
            "application": {"key": "D12345", "name": "Slack"},
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "out_of_date",
            "result": "denied",
            "user": {"name": "example@example.io"},
        },
    ),
]


class DUOUserEndpointFailure(PantherRule):
    RuleID = "DUO.User.Endpoint.Failure-prototype"
    DisplayName = "Duo User Denied For Endpoint Error"
    DedupPeriodMinutes = 15
    LogTypes = [LogType.Duo_Authentication]
    Tags = ["Duo"]
    Severity = PantherSeverity.Medium
    Description = "A Duo user's authentication was denied due to a suspicious error on the endpoint"
    Reference = "https://duo.com/docs/adminapi#authentication-logs"
    Runbook = (
        "Follow up with the endpoint owner to see status. Follow up with user to verify attempts."
    )
    Tests = duo_user_endpoint_failure_tests

    def rule(self, event):
        endpoint_reasons = [
            "endpoint_is_not_in_management_system",
            "endpoint_failed_google_verification",
            "endpoint_is_not_trusted",
            "could_not_determine_if_endpoint_was_trusted",
            "invalid_device",
        ]
        return event.get("reason", "") in endpoint_reasons

    def title(self, event):
        user = deep_get(event, "user", "name", default="Unknown")
        reason = event.get("reason", "Unknown")
        return f"Duo User [{user}] encountered suspicious endpoint issue [{reason}]"

    def alert_context(self, event):
        return {
            "factor": event.get("factor"),
            "reason": event.get("reason"),
            "user": deep_get(event, "user", "name", default=""),
            "os": deep_get(event, "access_device", "os", default=""),
            "ip_access": deep_get(event, "access_device", "ip", default=""),
            "ip_auth": deep_get(event, "auth_device", "ip", default=""),
            "application": deep_get(event, "application", "name", default=""),
        }
