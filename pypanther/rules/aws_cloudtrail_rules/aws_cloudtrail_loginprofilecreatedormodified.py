from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_cloud_trail_login_profile_created_or_modified_tests: list[RuleTest] = [
    RuleTest(
        name="ChangeOwnPassword",
        expected_result=False,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "1234",
            "eventName": "UpdateLoginProfile",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-09-15 13:45:24",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "987654321",
            "requestParameters": {"passwordResetRequired": False, "userName": "alice"},
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "ABC1234",
                "accountId": "987654321",
                "arn": "arn:aws:sts::98765432:assumed-role/IAM/alice",
                "principalId": "ABCDE:alice",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-09-15T13:36:47Z", "mfaAuthenticated": "true"},
                    "sessionIssuer": {
                        "accountId": "987654321",
                        "arn": "arn:aws:iam::9876432:role/IAM",
                        "principalId": "1234ABC",
                        "type": "Role",
                        "userName": "IAM",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="User changed password for other",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "1234",
            "eventName": "UpdateLoginProfile",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-09-15 13:45:24",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "987654321",
            "requestParameters": {"passwordResetRequired": False, "userName": "bob"},
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "ABC1234",
                "accountId": "987654321",
                "arn": "arn:aws:sts::98765432:assumed-role/IAM/alice",
                "principalId": "ABCDE:alice",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-09-15T13:36:47Z", "mfaAuthenticated": "true"},
                    "sessionIssuer": {
                        "accountId": "987654321",
                        "arn": "arn:aws:iam::9876432:role/IAM",
                        "principalId": "1234ABC",
                        "type": "Role",
                        "userName": "IAM",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
]


@panther_managed
class AWSCloudTrailLoginProfileCreatedOrModified(Rule):
    id = "AWS.CloudTrail.LoginProfileCreatedOrModified-prototype"
    display_name = "AWS User Login Profile Created or Modified"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0003:T1098", "TA0005:T1108", "TA0005:T1550", "TA0008:T1550"]}
    default_description = "An attacker with iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console. May be legitimate account administration."
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-pass-accesskeys-ssh.html"
    tests = aws_cloud_trail_login_profile_created_or_modified_tests
    PROFILE_EVENTS = {"UpdateLoginProfile", "CreateLoginProfile"}

    def rule(self, event):
        # Only look for successes
        if event.get("errorCode") or event.get("errorMessage"):
            return False
        # Check when someone other than the user themselves creates or modifies a login profile
        return (
            event.get("eventSource", "") == "iam.amazonaws.com"
            and event.get("eventName", "") in self.PROFILE_EVENTS
            and (
                not deep_get(event, "userIdentity", "arn", default="").endswith(
                    f"/{deep_get(event, 'requestParameters', 'userName', default='')}",
                )
            )
        )

    def title(self, event):
        return f"[{deep_get(event, 'userIdentity', 'arn')}] changed the password for [{deep_get(event, 'requestParameters', 'userName')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
