import logging

from panther_detection_helpers.caching import check_account_age

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSConsoleLoginWithoutMFA(Rule):
    id = "AWS.Console.LoginWithoutMFA-prototype"
    display_name = "Logins Without MFA"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity & Access Management", "Authentication", "Initial Access:Valid Accounts"]
    reports = {"CIS": ["3.2"], "MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.HIGH
    default_description = "A console login was made without multi-factor authentication."
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-console-login-without-mfa"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # Set to True for environments that permit direct role assumption via external IDP
    ROLES_VIA_EXTERNAL_IDP = False
    # pylint: disable=R0911,R0912,R1260

    def rule(self, event):
        if event.get("eventName") != "ConsoleLogin":
            return False
        # Extract some nested JSON structure
        additional_event_data = event.get("additionalEventData", {})
        response_elements = event.get("responseElements", {})
        user_identity_type = event.deep_get("userIdentity", "type", default="")
        # When there is an external IdP setup and users directly assume roles
        # the additionalData.MFAUsed attribute will be set to "no"
        #  AND the userIdentity.sessionContext.mfaAuthenticated attribute will be "false"
        #
        # This will create a lack of visibility into the condition where
        #  users are allowed to directly AssumeRole outside of the IdP and without MFA
        #
        # To date we have not identified data inside the log events that clearly
        #  delinates AssumeRole backed by an external IdP vs not backed by external IdP
        if self.ROLES_VIA_EXTERNAL_IDP and user_identity_type == "AssumedRole":
            return False
        # If using AWS SSOv2 or other SAML provider return False
        if (
            "AWSReservedSSO" in event.deep_get("userIdentity", "arn", default=" ")
            or additional_event_data.get("SamlProviderArn") is not None
        ):
            return False
        # If Account is less than 3 days old do not alert
        # This functionality is not enabled by default, in order to start logging new user creations
        # Enable indicator_creation_rules/new_account_logging to start logging new users
        new_user_string = (
            event.deep_get("userIdentity", "userName", default="<MISSING_USER_NAME>")
            + "-"
            + event.deep_get("userIdentity", "principalId", default="<MISSING_ID>")
        )
        is_new_user = check_account_age(new_user_string)
        if isinstance(is_new_user, str):
            logging.debug("check_account_age is a mocked string for unit testing")
            if is_new_user == "False":
                is_new_user = False
            if is_new_user == "True":
                is_new_user = True
        if is_new_user:
            return False
        new_account_string = "new_account - " + str(event.get("recipientAccountId"))
        is_new_account = check_account_age(new_account_string)
        if isinstance(is_new_account, str):
            logging.debug("check_account_age is a mocked string for unit testing")
            if is_new_account == "False":
                is_new_account = False
            if is_new_account == "True":
                is_new_account = True
        if is_new_account:
            return False
        if response_elements.get("ConsoleLogin") == "Success":
            # This logic is inverted because at times the second condition is None.
            # It is not recommended to remove this 'double negative"
            if (
                additional_event_data.get("MFAUsed") != "Yes"
                and event.deep_get("userIdentity", "sessionContext", "attributes", "mfaAuthenticated") != "true"
            ):
                return True
        return False

    def title(self, event):
        if event.deep_get("userIdentity", "type") == "Root":
            user_string = "the root user"
        else:
            user = event.deep_get("userIdentity", "userName") or event.deep_get(
                "userIdentity",
                "sessionContext",
                "sessionIssuer",
                "userName",
            )
            type_ = event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "type", default="user").lower()
            user_string = f"{type_} {user}"
        account_id = event.get("recipientAccountId")
        account_name = lookup_aws_account_name(account_id)
        if account_id == account_name:
            account_string = f"unnamed account ({account_id})"
        else:
            account_string = f"{account_name} account ({account_id})"
        return f"AWS login detected without MFA for [{user_string}] in [{account_string}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="No MFA Login - IAM User",
            expected_result=True,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="No MFA Login - IAM User Unknown Account",
            expected_result=True,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789013:user/tester",
                    "accountId": "123456789013",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789013",
            },
        ),
        RuleTest(
            name="No MFA Login - Root User",
            expected_result=True,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "accessKeyId": "",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "principalId": "123456789012",
                    "type": "Root",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="MFA Login - SAML",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/home",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                    "SamlProviderArn": "arn:aws:iam::123456789012:saml-provider/Okta",
                },
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="MFA Login",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "Yes",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="No MFA - Login Failed",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Failure"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "Yes",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="No MFA - authenticated from session with MFA",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "p_event_time": "2019-01-01 00:20:04.000Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "userIdentity": {
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/testrole_34c15ddd84cb4648/tester@example.com",
                    "principalId": "AROAXXXXXXXXXXXXXXXXX:tester@example.com",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-09-01T21:20:03Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/testrole_34c15ddd84cb4648",
                            "principalId": "AROAXXXXXXXXXXXXXXXXX",
                            "type": "Role",
                            "userName": "testrole_34c15ddd84cb4648",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="No MFA Login - New User",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="True")],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="AWS SSOv2 Login",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "additionalEventData": {"MFAUsed": "No", "MobileVersion": "No"},
                "awsRegion": "us-east-2",
                "eventID": "1111111111",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2022-03-16 19:17:41",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "xxx",
                "responseElements": {"ConsoleLogin": "Success"},
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
                "userIdentity": {
                    "accountId": "xxx",
                    "arn": "arn:aws:sts::xxx:assumed-role/AWSReservedSSO_developer_admin_asdf/foo@bar.com",
                    "principalId": "xxx:foo@bar.com",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-03-16T19:17:41Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "xxx",
                            "arn": "arn:aws:iam::xxx:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_developer_admin_asdf",
                            "principalId": "xxx",
                            "type": "Role",
                            "userName": "AWSReservedSSO_developer_admin_asdf",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="AssumeRole from MFA User Session",
            expected_result=False,
            mocks=[RuleMock(object_name="check_account_age", return_value="False")],
            log={
                "additionalEventData": {"MFAUsed": "No", "MobileVersion": "No"},
                "awsRegion": "us-east-1",
                "eventID": "sdsdsdsd",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2022-03-29 17:16:36.000000000",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111111111111111",
                "responseElements": {"ConsoleLogin": "Success"},
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36",
                "userIdentity": {
                    "accountId": "11111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-03-29T17:16:35Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {"accountId": "2222", "type": "Role", "userName": "asdsda"},
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="No MFA - IAM Role and External IDP",
            expected_result=False,
            mocks=[RuleMock(object_name="ROLES_VIA_EXTERNAL_IDP", return_value=True)],
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/SomeRole/1641313043312360000",
                    "principalId": "AROAXXXXXXXXXXXXXXXXX:1641313043312360000",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-01-04T16:17:27Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/SomeRole",
                            "principalId": "AROAXXXXXXXXXXXXXXXXX",
                            "type": "Role",
                            "userName": "SomeRole",
                        },
                    },
                    "type": "AssumedRole",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789013",
                "p_row_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "p_log_type": "AWS.CloudTrail",
            },
        ),
    ]
