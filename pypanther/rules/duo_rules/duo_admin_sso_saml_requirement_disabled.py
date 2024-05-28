from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_duo_helpers import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
)
from pypanther.log_types import LogType

duo_admin_ssosaml_requirement_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Enforcement Disabled",
        ExpectedResult=True,
        Log={
            "action": "admin_single_sign_on_update",
            "description": '{"enforcement_status": "disabled"}',
            "isotimestamp": "2021-10-12 21:29:22",
            "timestamp": "2021-10-12 21:29:22",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Enforcement Optional",
        ExpectedResult=True,
        Log={
            "action": "admin_single_sign_on_update",
            "description": '{"enforcement_status": "optional"}',
            "isotimestamp": "2021-10-12 21:29:22",
            "timestamp": "2021-10-12 21:29:22",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Enforcement Required",
        ExpectedResult=False,
        Log={
            "action": "admin_single_sign_on_update",
            "description": '{"enforcement_status": "required"}',
            "isotimestamp": "2021-10-12 21:29:22",
            "timestamp": "2021-10-12 21:29:22",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="SSO Update",
        ExpectedResult=False,
        Log={
            "action": "admin_single_sign_on_update",
            "description": '{"sso_url": "https://duff.okta.com/app/duoadminpanel/abcdefghijklm/sso/saml", "slo_url": null, "idp_type": "okta", "cert": "C=US/CN=duff/L=Springfield/O=Okta/OU=SSOProvider/ST=California/emailAddress=info@okta.com - 2031-08-10 13:39:00+00:00", "require_signed_response": true, "entity_id": "http://www.okta.com/abcdefghijk"}',
            "isotimestamp": "2021-10-12 21:33:40",
            "timestamp": "2021-10-12 21:33:40",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminSSOSAMLRequirementDisabled(PantherRule):
    Description = (
        "Detects when SAML Authentication for Administrators is marked as Disabled or Optional."
    )
    DisplayName = "Duo Admin SSO SAML Requirement Disabled"
    Reference = "https://duo.com/docs/sso#saml:~:text=Modify%20Authentication%20Sources"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.SSO.SAML.Requirement.Disabled-prototype"
    Tests = duo_admin_ssosaml_requirement_disabled_tests

    def rule(self, event):
        if event.get("action") == "admin_single_sign_on_update":
            description = deserialize_administrator_log_event_description(event)
            enforcement_status = description.get("enforcement_status", "required")
            return enforcement_status != "required"
        return False

    def title(self, event):
        description = deserialize_administrator_log_event_description(event)
        return f"Duo: [{event.get('username', '<username_not_found>')}] changed SAML authentication requirements for Administrators to [{description.get('enforcement_status', '<enforcement_status_not_found>')}]"

    def alert_context(self, event):
        return duo_alert_context(event)
