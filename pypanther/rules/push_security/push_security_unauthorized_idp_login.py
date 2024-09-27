from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class PushSecurityUnauthorizedIdPLogin(Rule):
    id = "Push.Security.Unauthorized.IdP.Login-prototype"
    display_name = "Push Security Unauthorized IdP Login"
    enabled = False
    tags = ["Configuration Required"]
    log_types = [LogType.PUSH_SECURITY_ACTIVITY]
    default_severity = Severity.HIGH
    default_description = (
        "Login to application with unauthorized identity provider which could indicate a SAMLjacking attack."
    )
    default_reference = "https://github.com/pushsecurity/saas-attacks/blob/main/techniques/samljacking/description.md"
    # Configure allowed identity provider logins to SaaS apps
    allowed_idps = {
        "GOOGLE_WORKSPACE": {"OIDC_LOGIN", "SAML_LOGIN"},
        "OKTA": {"PASSWORD_LOGIN"},
        None: {"PASSWORD_LOGIN"},
    }

    def rule(self, event):
        if event.get("object") != "LOGIN":
            return False
        identity_provider = event.deep_get("new", "identityProvider")
        login_type = event.deep_get("new", "loginType")
        if identity_provider in self.allowed_idps and login_type in self.allowed_idps[identity_provider]:
            return False
        return True

    def title(self, event):
        identity_provider = event.deep_get("new", "identityProvider", default="Null identityProvider")
        login_type = event.deep_get("new", "loginType", default="Null loginType")
        app_type = event.deep_get("new", "appType", default="Null appType")
        new_email = event.deep_get("new", "email")
        return f"Unauthorized identity provider in use. User: {new_email}         used {identity_provider} {login_type} on {app_type}"

    tests = [
        RuleTest(
            name="Google Workspace Password Login",
            expected_result=True,
            log={
                "id": "d240e3f2-3cd6-425f-a835-dad0ff237d09",
                "new": {
                    "accountId": "a93b45a7-fdce-489e-b76d-2bd6862a62ba",
                    "appId": "8348ca36-d254-4e1b-8f31-6837d82fc5cb",
                    "appType": "GOOGLE_WORKSPACE",
                    "browser": "EDGE",
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "identityProvider": "GOOGLE_WORKSPACE",
                    "leakedPassword": False,
                    "loginTimestamp": 1707773386.0,
                    "loginType": "PASSWORD_LOGIN",
                    "os": "WINDOWS",
                    "passwordId": "6ae9f0b2-9300-43f0-b210-c0d3c16640f8",
                    "passwordManuallyTyped": False,
                    "sourceIpAddress": "35.90.103.134",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
                    "weakPassword": False,
                    "weakPasswordReasons": None,
                },
                "object": "LOGIN",
                "timestamp": 1707774319.0,
                "version": "1",
            },
        ),
        RuleTest(
            name="Microsoft 365 OIDC Login",
            expected_result=True,
            log={
                "id": "d240e3f2-3cd6-425f-a835-dad0ff237d09",
                "new": {
                    "accountId": "a93b45a7-fdce-489e-b76d-2bd6862a62ba",
                    "appId": "8348ca36-d254-4e1b-8f31-6837d82fc5cb",
                    "appType": "DROPBOX",
                    "browser": "EDGE",
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "identityProvider": "MICROSOFT_365",
                    "leakedPassword": False,
                    "loginTimestamp": 1707773386.0,
                    "loginType": "OIDC_LOGIN",
                    "os": "WINDOWS",
                    "passwordId": "6ae9f0b2-9300-43f0-b210-c0d3c16640f8",
                    "passwordManuallyTyped": False,
                    "sourceIpAddress": "35.90.103.134",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
                    "weakPassword": False,
                    "weakPasswordReasons": None,
                },
                "object": "LOGIN",
                "timestamp": 1707774319.0,
                "version": "1",
            },
        ),
        RuleTest(
            name="Password Login",
            expected_result=False,
            log={
                "id": "d240e3f2-3cd6-425f-a835-dad0ff237d09",
                "new": {
                    "accountId": "a93b45a7-fdce-489e-b76d-2bd6862a62ba",
                    "appId": "8348ca36-d254-4e1b-8f31-6837d82fc5cb",
                    "appType": "DROPBOX",
                    "browser": "EDGE",
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "identityProvider": None,
                    "leakedPassword": False,
                    "loginTimestamp": 1707773386.0,
                    "loginType": "PASSWORD_LOGIN",
                    "os": "WINDOWS",
                    "passwordId": "6ae9f0b2-9300-43f0-b210-c0d3c16640f8",
                    "passwordManuallyTyped": False,
                    "sourceIpAddress": "35.90.103.134",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
                    "weakPassword": False,
                    "weakPasswordReasons": None,
                },
                "object": "LOGIN",
                "timestamp": 1707774319.0,
                "version": "1",
            },
        ),
    ]
