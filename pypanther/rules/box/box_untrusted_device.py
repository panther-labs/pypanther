from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class BoxUntrustedDevice(Rule):
    id = "Box.Untrusted.Device-prototype"
    display_name = "Box Untrusted Device Login"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Initial Access:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.INFO
    create_alert = False
    default_description = "A user attempted to login from an untrusted device.\n"
    default_reference = (
        "https://support.box.com/hc/en-us/articles/360044194993-Setting-Up-Device-Trust-Security-Requirements"
    )
    default_runbook = "Investigate whether this is a valid user attempting to login to box.\n"
    summary_attributes = ["ip_address"]

    def rule(self, event):
        # DEVICE_TRUST_CHECK_FAILED
        #  detect when a user attempts to login from an untrusted device
        return event.get("event_type") == "DEVICE_TRUST_CHECK_FAILED"

    def title(self, event):
        return f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] attempted to login from an untrusted device."

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
            name="New Login Event",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DEVICE_TRUST_CHECK_FAILED",
                "source": {"id": "12345678", "type": "user", "login": "user@example"},
            },
        ),
    ]
