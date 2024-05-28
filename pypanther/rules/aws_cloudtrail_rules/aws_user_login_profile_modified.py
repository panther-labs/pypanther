from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

aws_user_login_profile_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="ChangeOwnPassword",
        ExpectedResult=False,
        Log={
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
                    "attributes": {
                        "creationDate": "2022-09-15T13:36:47Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="User changed password for other",
        ExpectedResult=True,
        Log={
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
                    "attributes": {
                        "creationDate": "2022-09-15T13:36:47Z",
                        "mfaAuthenticated": "true",
                    },
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
    PantherRuleTest(
        Name="User changed password for other reset required",
        ExpectedResult=False,
        Log={
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
            "requestParameters": {"passwordResetRequired": True, "userName": "bob"},
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "ABC1234",
                "accountId": "987654321",
                "arn": "arn:aws:sts::98765432:assumed-role/IAM/alice",
                "principalId": "ABCDE:alice",
                "sessionContext": {
                    "attributes": {
                        "creationDate": "2022-09-15T13:36:47Z",
                        "mfaAuthenticated": "true",
                    },
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


class AWSUserLoginProfileModified(PantherRule):
    Description = "An attacker with iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console. May be legitimate account administration."
    DisplayName = "AWS User Login Profile Modified"
    Reports = {"MITRE ATT&CK": ["TA0003:T1098", "TA0005:T1108", "TA0005:T1550", "TA0008:T1550"]}
    Reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-pass-accesskeys-ssh.html"
    Severity = PantherSeverity.High
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.User.Login.Profile.Modified-prototype"
    Tests = aws_user_login_profile_modified_tests

    def rule(self, event):
        return (
            event.get("eventSource", "") == "iam.amazonaws.com"
            and event.get("eventName", "") == "UpdateLoginProfile"
            and (not deep_get(event, "requestParameters", "passwordResetRequired", default=False))
            and (
                not deep_get(event, "userIdentity", "arn", default="").endswith(
                    f"/{deep_get(event, 'requestParameters', 'userName', default='')}"
                )
            )
        )

    def title(self, event):
        return f"User [{deep_get(event, 'userIdentity', 'arn').split('/')[-1]}] changed the password for [{deep_get(event, 'requestParameters', 'userName')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
