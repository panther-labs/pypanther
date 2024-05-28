from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_duo_helpers import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
)
from pypanther.log_types import LogType

duo_admin_create_admin_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Admin Create",
        ExpectedResult=True,
        Log={
            "action": "admin_create",
            "description": '{"name": "Homer Simpson", "phone": null, "is_temporary_password": false, "email": "homer.simpson@simpsons.com", "hardtoken": null, "role": "Owner", "status": "Pending Activation", "restricted_by_admin_units": false, "administrative_units": ""}',
            "isotimestamp": "2023-01-17 16:47:54",
            "object": "Homer Simpson",
            "timestamp": "2023-01-17 16:47:54",
            "username": "Bart Simpson",
        },
    ),
    PantherRuleTest(
        Name="Other Event",
        ExpectedResult=False,
        Log={
            "action": "admin_login",
            "description": '{"ip_address": "1.2.3.4", "device": "123-456-123", "factor": "sms", "saml_idp": "OneLogin", "primary_auth_method": "Single Sign-On"}',
            "isotimestamp": "2021-07-02 18:31:25",
            "timestamp": "2021-07-02 18:31:25",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminCreateAdmin(PantherRule):
    Description = "A new Duo Administrator was created. "
    DisplayName = "Duo Admin Create Admin"
    Reference = "https://duo.com/docs/administration-admins#add-an-administrator"
    Severity = PantherSeverity.High
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.Create.Admin-prototype"
    Tests = duo_admin_create_admin_tests

    def rule(self, event):
        return event.get("action") == "admin_create"

    def title(self, event):
        event_description = deserialize_administrator_log_event_description(event)
        return f"Duo: [{event.get('username', '<username_not_found>')}] created a new admin account: [{event_description.get('name', '<name_not_found>')}] [{event_description.get('email', '<email_not_found>')}]."

    def alert_context(self, event):
        return duo_alert_context(event)
