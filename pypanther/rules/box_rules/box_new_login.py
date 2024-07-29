from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

box_new_login_tests: list[RuleTest] = [
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
            "event_type": "ADD_LOGIN_ACTIVITY_DEVICE",
            "source": {"id": "12345678", "type": "user", "login": "user@example"},
        },
    ),
]


@panther_managed
class BoxNewLogin(Rule):
    id = "Box.New.Login-prototype"
    display_name = "Box New Login"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Initial Access:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.INFO
    default_description = "A user logged in from a new device.\n"
    default_reference = "https://support.box.com/hc/en-us/articles/360043691914-Controlling-Devices-Used-to-Access-Box"
    default_runbook = "Investigate whether this is a valid user login.\n"
    summary_attributes = ["ip_address"]
    tests = box_new_login_tests

    def rule(self, event):
        # ADD_LOGIN_ACTIVITY_DEVICE
        #  detect when a user logs in from a device not previously seen
        return event.get("event_type") == "ADD_LOGIN_ACTIVITY_DEVICE"

    def title(self, event):
        return f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] logged in from a new device."
