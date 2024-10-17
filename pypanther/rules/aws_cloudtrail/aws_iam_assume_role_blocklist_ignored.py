from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailIAMAssumeRoleBlacklistIgnored(Rule):
    id = "AWS.CloudTrail.IAMAssumeRoleBlacklistIgnored-prototype"
    display_name = "IAM Assume Role Blocklist Ignored"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = [
        "AWS",
        "Configuration Required",
        "Identity and Access Management",
        "Privilege Escalation:Abuse Elevation Control Mechanism",
    ]
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH
    default_description = "A user assumed a role that was explicitly blocklisted for manual user assumption.\n"
    default_runbook = "Verify that this was an approved assume role action. If not, consider revoking the access immediately and updating the AssumeRolePolicyDocument to prevent this from happening again.\n"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # This is a list of role ARNs that should not be assumed by users in normal operations
    ASSUME_ROLE_BLOCKLIST = ["arn:aws:iam::123456789012:role/FullAdminRole"]

    def rule(self, event):
        # Only considering successful AssumeRole action
        if not aws_cloudtrail_success(event) or event.get("eventName") != "AssumeRole":
            return False
        # Only considering user actions
        if event.deep_get("userIdentity", "type") not in ["IAMUser", "FederatedUser"]:
            return False
        return event.deep_get("requestParameters", "roleArn") in self.ASSUME_ROLE_BLOCKLIST

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="IAM Blocklisted Role Assumed",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "durationSeconds": 900,
                    "roleArn": "arn:aws:iam::123456789012:role/FullAdminRole",
                    "roleSessionName": "1111",
                },
                "resources": [
                    {
                        "ARN": "arn:aws:iam::123456789012:role/FullAdminRole",
                        "accountId": "123456789012",
                        "type": "AWS::IAM::Role",
                    },
                ],
                "responseElements": {
                    "assumedRoleUser": {
                        "arn": "arn:aws:sts::123456789012:assumed-role/FullAdminRole/1111",
                        "assumedRoleId": "ABCD:1111",
                    },
                    "credentials": {
                        "accessKeyId": "1111",
                        "expiration": "Jan 01, 2019 0:00:00 PM",
                        "sessionToken": "1111",
                    },
                },
                "sharedEventID": "1111",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "aws-sdk-go/1.4.14 (go1.11.4; darwin; amd64)",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:user/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                    },
                    "type": "IAMUser",
                    "userName": "example-user",
                },
            },
        ),
        RuleTest(
            name="IAM Non Blocklisted Role Assumed",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventID": "1111",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "durationSeconds": 900,
                    "roleArn": "arn:aws:iam::123456789012:role/example-role",
                    "roleSessionName": "1111",
                },
                "resources": [
                    {
                        "ARN": "arn:aws:iam::123456789012:role/example-role",
                        "accountId": "123456789012",
                        "type": "AWS::IAM::Role",
                    },
                ],
                "responseElements": {
                    "assumedRoleUser": {
                        "arn": "arn:aws:sts::123456789012:assumed-role/example-role/1111",
                        "assumedRoleId": "ABCD:1111",
                    },
                    "credentials": {
                        "accessKeyId": "1111",
                        "expiration": "Jan 01, 2019 0:00:00 PM",
                        "sessionToken": "1111",
                    },
                },
                "sharedEventID": "1111",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "aws-sdk-go/1.4.14 (go1.11.4; darwin; amd64)",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:user/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                    },
                    "type": "IAMUser",
                    "userName": "example-user",
                },
            },
        ),
        RuleTest(
            name="Error Assuming IAM Blocked Role",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "errorCode": "ExpiredToken",
                "eventID": "1111",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "durationSeconds": 900,
                    "roleArn": "arn:aws:iam::123456789012:role/FullAdminRole",
                    "roleSessionName": "1111",
                },
                "resources": [
                    {
                        "ARN": "arn:aws:iam::123456789012:role/FullAdminRole",
                        "accountId": "123456789012",
                        "type": "AWS::IAM::Role",
                    },
                ],
                "responseElements": {
                    "assumedRoleUser": {
                        "arn": "arn:aws:sts::123456789012:assumed-role/FullAdminRole/1111",
                        "assumedRoleId": "ABCD:1111",
                    },
                    "credentials": {
                        "accessKeyId": "1111",
                        "expiration": "Jan 01, 2019 0:00:00 PM",
                        "sessionToken": "1111",
                    },
                },
                "sharedEventID": "1111",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "aws-sdk-go/1.4.14 (go1.11.4; darwin; amd64)",
                "userIdentity": {
                    "accesKeyId": "1111",
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:user/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                    },
                    "type": "IAMUser",
                    "userName": "example-user",
                },
            },
        ),
    ]
