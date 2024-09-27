from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class PushSecurityNewSaaSAccountCreated(Rule):
    id = "Push.Security.New.SaaS.Account.Created-prototype"
    display_name = "Push Security New SaaS Account Created"
    log_types = [LogType.PUSH_SECURITY_ENTITIES]
    default_severity = Severity.INFO

    def rule(self, event):
        if event.get("object") != "ACCOUNT":
            return False
        if event.get("type") == "CREATE":
            return True
        return False

    def title(self, event):
        app_type = event.deep_get("new", "appType")
        new_email = event.deep_get("new", "email")
        return f"New account on {app_type} created by {new_email}"

    tests = [
        RuleTest(
            name="Account Update",
            expected_result=False,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "appType": "ATLASSIAN",
                    "creationTimestamp": 1698064423.0,
                    "email": "john.hill@example.com",
                    "employeeId": "72d0347a-2663-4ef5-b1c5-df39163f1603",
                    "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                    "lastUsedTimestamp": 1698669168.0,
                    "loginMethods": {
                        "oidcLogin": "GOOGLE_WORKSPACE",
                        "oktaSwaLogin": True,
                        "passwordLogin": True,
                        "samlLogin": "OKTA",
                        "vendorSsoLogin": "GOOGLE_WORKSPACE",
                    },
                    "mfaMethods": [
                        "APP_TOTP",
                        "PUSH_NOTIFICATION",
                        "EMAIL_OTP",
                        "U2F",
                        "HARDWARE_TOTP",
                        "PHONE_CALL",
                        "SMS_OTP",
                        "APP_PASSWORD",
                        "GRID_CARD",
                        "EXTERNAL_PROVIDER",
                        "BACKUP_CODES",
                        "WEBAUTHN",
                    ],
                    "mfaRegistered": True,
                    "passwordId": "4c13674f-e88a-4411-bfa2-53a70468a898",
                },
                "object": "ACCOUNT",
                "old": {
                    "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "appType": "ATLASSIAN",
                    "creationTimestamp": 1698064423.0,
                    "email": "john.hill@example.com",
                    "employeeId": "72d0347a-2663-4ef5-b1c5-df39163f1603",
                    "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                    "lastUsedTimestamp": 1698669168.0,
                    "loginMethods": {
                        "oidcLogin": "GOOGLE_WORKSPACE",
                        "oktaSwaLogin": True,
                        "passwordLogin": True,
                        "samlLogin": "OKTA",
                        "vendorSsoLogin": "GOOGLE_WORKSPACE",
                    },
                    "mfaMethods": [
                        "APP_TOTP",
                        "PUSH_NOTIFICATION",
                        "EMAIL_OTP",
                        "U2F",
                        "HARDWARE_TOTP",
                        "PHONE_CALL",
                        "SMS_OTP",
                        "APP_PASSWORD",
                        "GRID_CARD",
                        "EXTERNAL_PROVIDER",
                        "BACKUP_CODES",
                        "WEBAUTHN",
                    ],
                    "mfaRegistered": True,
                    "passwordId": "4c13674f-e88a-4411-bfa2-53a70468a898",
                },
                "timestamp": 1698604061.0,
                "type": "UPDATE",
                "version": "1",
            },
        ),
        RuleTest(
            name="New Account",
            expected_result=True,
            log={
                "id": "c478966c-f927-411c-b919-179832d3d50c",
                "new": {
                    "appId": "2a2197de-ad2c-47e4-8dcb-fb0f04cf83e0",
                    "appType": "ATLASSIAN",
                    "creationTimestamp": 1698064423.0,
                    "email": "john.hill@example.com",
                    "employeeId": "72d0347a-2663-4ef5-b1c5-df39163f1603",
                    "id": "d6a32ba5-0532-4a66-8137-48cdf409c972",
                    "lastUsedTimestamp": 1698669168.0,
                    "loginMethods": {
                        "oidcLogin": "GOOGLE_WORKSPACE",
                        "oktaSwaLogin": True,
                        "passwordLogin": True,
                        "samlLogin": "OKTA",
                        "vendorSsoLogin": "GOOGLE_WORKSPACE",
                    },
                    "mfaMethods": [
                        "APP_TOTP",
                        "PUSH_NOTIFICATION",
                        "EMAIL_OTP",
                        "U2F",
                        "HARDWARE_TOTP",
                        "PHONE_CALL",
                        "SMS_OTP",
                        "APP_PASSWORD",
                        "GRID_CARD",
                        "EXTERNAL_PROVIDER",
                        "BACKUP_CODES",
                        "WEBAUTHN",
                    ],
                    "mfaRegistered": True,
                    "passwordId": "4c13674f-e88a-4411-bfa2-53a70468a898",
                },
                "object": "ACCOUNT",
                "old": None,
                "timestamp": 1698604061.0,
                "type": "CREATE",
                "version": "1",
            },
        ),
    ]
