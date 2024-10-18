from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DUOUserEndpointFailure(Rule):
    id = "DUO.User.Endpoint.Failure-prototype"
    display_name = "Duo User Denied For Endpoint Error"
    dedup_period_minutes = 15
    log_types = [LogType.DUO_AUTHENTICATION]
    tags = ["Duo"]
    default_severity = Severity.MEDIUM
    default_description = "A Duo user's authentication was denied due to a suspicious error on the endpoint"
    default_reference = "https://duo.com/docs/adminapi#authentication-logs"
    default_runbook = "Follow up with the endpoint owner to see status. Follow up with user to verify attempts."

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
        user = event.deep_get("user", "name", default="Unknown")
        reason = event.get("reason", "Unknown")
        return f"Duo User [{user}] encountered suspicious endpoint issue [{reason}]"

    def alert_context(self, event):
        return {
            "factor": event.get("factor"),
            "reason": event.get("reason"),
            "user": event.deep_get("user", "name", default=""),
            "os": event.deep_get("access_device", "os", default=""),
            "ip_access": event.deep_get("access_device", "ip", default=""),
            "ip_auth": event.deep_get("auth_device", "ip", default=""),
            "application": event.deep_get("application", "name", default=""),
        }

    tests = [
        RuleTest(
            name="endpoint_is_not_in_management_system",
            expected_result=True,
            log={
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
        RuleTest(
            name="endpoint_failed_google_verification",
            expected_result=True,
            log={
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
        RuleTest(
            name="endpoint_is_not_trusted",
            expected_result=True,
            log={
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
        RuleTest(
            name="could_not_determine_if_endpoint_was_trusted",
            expected_result=True,
            log={
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
        RuleTest(
            name="invalid_device",
            expected_result=True,
            log={
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
        RuleTest(
            name="good_auth",
            expected_result=False,
            log={
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
        RuleTest(
            name="denied_old_creds",
            expected_result=False,
            log={
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
