from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_login_type_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Login With Approved Type",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_success",
            "parameters": {"login_type": "saml"},
        },
    ),
    PantherRuleTest(
        Name="Login With Unapproved Type",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "login"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_success",
            "parameters": {"login_type": "turbo-snail"},
        },
    ),
    PantherRuleTest(
        Name="Non-Login event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "logout"},
            "actor": {"email": "some.user@somedomain.com"},
            "type": "login",
            "name": "login_success",
            "parameters": {"login_type": "saml"},
        },
    ),
    PantherRuleTest(
        Name="Saml Login Event",
        ExpectedResult=False,
        Log={
            "actor": {"email": "some.user@somedomain.com"},
            "id": {"applicationName": "saml", "time": "2022-05-26 15:26:09.421000000"},
            "ipAddress": "10.10.10.10",
            "kind": "admin#reports#activity",
            "name": "login_success",
            "parameters": {
                "application_name": "Some SAML Application",
                "initiated_by": "sp",
                "orgunit_path": "/SomeOrgUnit",
                "saml_status_code": "SUCCESS_URI",
            },
            "type": "login",
        },
    ),
]


class GSuiteLoginType(PantherRule):
    RuleID = "GSuite.LoginType-prototype"
    DisplayName = "GSuite Login Type"
    Enabled = False
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Configuration Required", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = PantherSeverity.Medium
    Description = "A login of a non-approved type was detected for this user.\n"
    Reference = "https://support.google.com/a/answer/9039184?hl=en&sjid=864417124752637253-EU"
    Runbook = (
        "Correct the user account settings so that only logins of approved types are available.\n"
    )
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_login_type_tests
    # allow-list of approved login types
    APPROVED_LOGIN_TYPES = {"exchange", "google_password", "reauth", "saml", "unknown"}
    # allow-list any application names here
    APPROVED_APPLICATION_NAMES = {"saml"}

    def rule(self, event):
        if event.get("type") != "login":
            return False
        if event.get("name") == "logout":
            return False
        if (
            deep_get(event, "parameters", "login_type") in self.APPROVED_LOGIN_TYPES
            or deep_get(event, "id", "applicationName") in self.APPROVED_APPLICATION_NAMES
        ):
            return False
        return True

    def title(self, event):
        return f"A login attempt of a non-approved type was detected for user [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
