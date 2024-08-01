from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

retrieve_ss_oaccesstoken_tests: list[RuleTest] = [
    RuleTest(
        name="Retrieve SSO access token",
        expected_result=True,
        log={
            "eventName": "CreateToken",
            "eventSource": "sso.amazonaws.com",
            "eventVersion": "1.08",
            "recipientAccountId": "<organization master account ID>",
            "requestParameters": {
                "clientId": "...",
                "clientSecret": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "deviceCode": "...",
                "grantType": "urn:ietf:params:oauth:grant-type:device_code",
            },
            "responseElements": {
                "accessToken": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "expiresIn": 28800,
                "idToken": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "refreshToken": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "tokenType": "Bearer",
            },
            "sourceIPAddress": "<Attacker source IP>",
            "userAgent": "<Attacker user agent (here: Boto3/1.17.80 Python/3.9.5 Darwin/20.3.0 Botocore/1.20.80)>",
            "userIdentity": {
                "accountId": "<organization master account ID>",
                "principalId": "<internal victim user id>",
                "type": "Unknown",
                "userName": "<victim display name>",
            },
        },
    ),
]


@panther_managed
class RetrieveSSOaccesstoken(Rule):
    id = "Retrieve.SSO.access.token-prototype"
    display_name = "SIGNAL - Retrieve SSO access token"
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    tests = retrieve_ss_oaccesstoken_tests

    def rule(self, event):
        return event.get("eventSource") == "sso.amazonaws.com" and event.get("eventName") == "CreateToken"
