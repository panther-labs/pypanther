from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class PushSecurityPhishableMFAMethod(Rule):
    id = "Push.Security.Phishable.MFA.Method-prototype"
    display_name = "Push Security Phishable MFA Method"
    log_types = [LogType.PUSH_SECURITY_ENTITIES]
    default_severity = Severity.INFO
    identity_providers = ("MICROSOFT_365", "GOOGLE_WORKSPACE", "OKTA", "JUMPCLOUD", "PING")
    phishable_mfa = ("EMAIL_OTP", "PHONE_CALL", "SMS", "APP_PASSWORD")

    def rule(self, event):
        if event.get("object") != "ACCOUNT":
            return False
        mfa_methods = event.deep_get("new", "mfaMethods")
        for method in mfa_methods:
            if method in self.phishable_mfa:
                return True
        return False

    def severity(self, event):
        if event.deep_get("new", "appType") in self.identity_providers:
            return "HIGH"
        return "INFO"

    def title(self, event):
        mfa_methods = ", ".join(event.deep_get("new", "mfaMethods", default="No MFA"))
        new_email = event.deep_get("new", "email")
        app_type = event.deep_get("new", "appType", default=[])
        return f"{new_email} using phisbable MFA method with {app_type}.             MFA methods enabled: {mfa_methods}"

    tests = [
        RuleTest(
            name="Dropbox Phishable MFA",
            expected_result=True,
            log={
                "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
                "new": {
                    "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                    "appType": "DROPBOX",
                    "creationTimestamp": 1707775048.0,
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                    "lastUsedTimestamp": None,
                    "loginMethods": {
                        "oidcLogin": None,
                        "oktaSwaLogin": False,
                        "passwordLogin": False,
                        "samlLogin": None,
                    },
                    "mfaMethods": ["SMS", "EMAIL_OTP"],
                    "mfaRegistered": False,
                    "passwordId": None,
                },
                "object": "ACCOUNT",
                "old": None,
            },
        ),
        RuleTest(
            name="Google Workspace Phishable MFA",
            expected_result=True,
            log={
                "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
                "new": {
                    "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                    "appType": "GOOGLE_WORKSPACE",
                    "creationTimestamp": 1707775048.0,
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                    "lastUsedTimestamp": None,
                    "loginMethods": {
                        "oidcLogin": None,
                        "oktaSwaLogin": False,
                        "passwordLogin": False,
                        "samlLogin": None,
                    },
                    "mfaMethods": ["SMS", "EMAIL_OTP"],
                    "mfaRegistered": False,
                    "passwordId": None,
                },
                "object": "ACCOUNT",
                "old": None,
            },
        ),
        RuleTest(
            name="No MFA Enabled",
            expected_result=False,
            log={
                "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
                "new": {
                    "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                    "appType": "CONTENTFUL",
                    "creationTimestamp": 1707775048.0,
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                    "lastUsedTimestamp": None,
                    "loginMethods": {
                        "oidcLogin": None,
                        "oktaSwaLogin": False,
                        "passwordLogin": False,
                        "samlLogin": None,
                    },
                    "mfaMethods": [],
                    "mfaRegistered": False,
                    "passwordId": None,
                },
                "object": "ACCOUNT",
                "old": {
                    "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                    "appType": "CONTENTFUL",
                    "creationTimestamp": 1707775048.0,
                    "email": "jet.black@issp.com",
                    "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                    "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                    "lastUsedTimestamp": None,
                    "loginMethods": {
                        "oidcLogin": None,
                        "oktaSwaLogin": False,
                        "passwordLogin": False,
                        "samlLogin": None,
                    },
                    "mfaMethods": [],
                    "mfaRegistered": False,
                    "passwordId": None,
                },
                "timestamp": 1707775049.0,
                "type": "CREATE",
                "version": "1",
            },
        ),
    ]
