from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSUserLoginProfileModified(Rule):
    default_description = "An attacker with iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console. May be legitimate account administration."
    display_name = "AWS User Login Profile Modified"
    reports = {"MITRE ATT&CK": ["TA0003:T1098", "TA0005:T1108", "TA0005:T1550", "TA0008:T1550"]}
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-pass-accesskeys-ssh.html"
    default_severity = Severity.HIGH
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.User.Login.Profile.Modified-prototype"

    def rule(self, event):
        return (
            event.get("eventSource", "") == "iam.amazonaws.com"
            and event.get("eventName", "") == "UpdateLoginProfile"
            and (not event.deep_get("requestParameters", "passwordResetRequired", default=False))
            and (
                not event.deep_get("userIdentity", "arn", default="").endswith(
                    f"/{event.deep_get('requestParameters', 'userName', default='')}",
                )
            )
        )

    def title(self, event):
        return f"User [{event.deep_get('userIdentity', 'arn').split('/')[-1]}] changed the password for [{event.deep_get('requestParameters', 'userName')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
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
        RuleTest(
            name="User changed password for other reset required",
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
