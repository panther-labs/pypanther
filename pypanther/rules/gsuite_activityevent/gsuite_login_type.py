from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteLoginType(Rule):
    id = "GSuite.LoginType-prototype"
    display_name = "GSuite Login Type"
    enabled = False
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Configuration Required", "Initial Access:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.MEDIUM
    default_description = "A login of a non-approved type was detected for this user.\n"
    default_reference = "https://support.google.com/a/answer/9039184?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Correct the user account settings so that only logins of approved types are available.\n"
    summary_attributes = ["actor:email"]
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
            event.deep_get("parameters", "login_type") in self.APPROVED_LOGIN_TYPES
            or event.deep_get("id", "applicationName") in self.APPROVED_APPLICATION_NAMES
        ):
            return False
        return True

    def title(self, event):
        return f"A login attempt of a non-approved type was detected for user [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"

    tests = [
        RuleTest(
            name="Login With Approved Type",
            expected_result=False,
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": "some.user@somedomain.com"},
                "type": "login",
                "name": "login_success",
                "parameters": {"login_type": "saml"},
            },
        ),
        RuleTest(
            name="Login With Unapproved Type",
            expected_result=True,
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": "some.user@somedomain.com"},
                "type": "login",
                "name": "login_success",
                "parameters": {"login_type": "turbo-snail"},
            },
        ),
        RuleTest(
            name="Non-Login event",
            expected_result=False,
            log={
                "id": {"applicationName": "logout"},
                "actor": {"email": "some.user@somedomain.com"},
                "type": "login",
                "name": "login_success",
                "parameters": {"login_type": "saml"},
            },
        ),
        RuleTest(
            name="Saml Login Event",
            expected_result=False,
            log={
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
