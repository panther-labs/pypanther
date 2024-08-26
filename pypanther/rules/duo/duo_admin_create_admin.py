from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_duo_helpers import deserialize_administrator_log_event_description, duo_alert_context

duo_admin_create_admin_tests: list[RuleTest] = [
    RuleTest(
        name="Admin Create",
        expected_result=True,
        log={
            "action": "admin_create",
            "description": '{"name": "Homer Simpson", "phone": null, "is_temporary_password": false, "email": "homer.simpson@simpsons.com", "hardtoken": null, "role": "Owner", "status": "Pending Activation", "restricted_by_admin_units": false, "administrative_units": ""}',
            "isotimestamp": "2023-01-17 16:47:54",
            "object": "Homer Simpson",
            "timestamp": "2023-01-17 16:47:54",
            "username": "Bart Simpson",
        },
    ),
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
            "action": "admin_login",
            "description": '{"ip_address": "1.2.3.4", "device": "123-456-123", "factor": "sms", "saml_idp": "OneLogin", "primary_auth_method": "Single Sign-On"}',
            "isotimestamp": "2021-07-02 18:31:25",
            "timestamp": "2021-07-02 18:31:25",
            "username": "Homer Simpson",
        },
    ),
]


@panther_managed
class DuoAdminCreateAdmin(Rule):
    default_description = "A new Duo Administrator was created. "
    display_name = "Duo Admin Create Admin"
    default_reference = "https://duo.com/docs/administration-admins#add-an-administrator"
    default_severity = Severity.HIGH
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.Create.Admin-prototype"
    tests = duo_admin_create_admin_tests

    def rule(self, event):
        return event.get("action") == "admin_create"

    def title(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return f"Duo: [{event.get('username', '<username_not_found>')}] created a new admin account: [{event_description.get('name', '<name_not_found>')}] [{event_description.get('email', '<email_not_found>')}]."

    def alert_context(self, event):
        return duo_alert_context(event)
