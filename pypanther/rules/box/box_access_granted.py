from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class BoxAccessGranted(Rule):
    id = "Box.Access.Granted-prototype"
    display_name = "Box Access Granted"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box"]
    default_severity = Severity.LOW
    default_description = "A user granted access to their box account to Box technical support from account settings.\n"
    default_reference = (
        "https://support.box.com/hc/en-us/articles/7039943421715-Enabling-and-Disabling-Access-for-Box-Support"
    )
    default_runbook = "Investigate whether the user purposefully granted access to their account.\n"
    summary_attributes = ["p_any_ip_addresses"]

    def rule(self, event):
        return event.get("event_type") == "ACCESS_GRANTED"

    def title(self, event):
        return (
            f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] granted access to their account"
        )

    tests = [
        RuleTest(
            name="Regular Event",
            expected_result=False,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DELETE",
            },
        ),
        RuleTest(
            name="Access Granted",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "ACCESS_GRANTED",
                "source": {"id": "12345678", "type": "user", "login": "user@example", "name": "Bob Cat"},
            },
        ),
    ]
