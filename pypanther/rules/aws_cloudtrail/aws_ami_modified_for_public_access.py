from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailAMIModifiedForPublicAccess(Rule):
    id = "AWS.CloudTrail.AMIModifiedForPublicAccess-prototype"
    display_name = "Amazon Machine Image (AMI) Modified to Allow Public Access"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Exfiltration:Transfer Data to Cloud Account"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    default_description = "An Amazon Machine Image (AMI) was modified to allow it to be launched by anyone. Any sensitive configuration or application data stored in the AMI's block devices is at risk.\n"
    default_runbook = "Determine if the AMI is intended to be publicly accessible. If not, first modify the AMI to not be publicly accessible then change any sensitive data stored in the block devices associated to the AMI (as they may be compromised).\n"
    default_reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html"
    summary_attributes = ["userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        # Only check successful ModiyImageAttribute events
        if not aws_cloudtrail_success(event) or event.get("eventName") != "ModifyImageAttribute":
            return False
        added_perms = event.deep_get("requestParameters", "launchPermission", "add", "items", default=[])
        for item in added_perms:
            if item.get("group") == "all":
                return True
        return False

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="AMI Made Public",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "ModifyImageAttribute",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "attributeType": "launchPermission",
                    "imageId": "ami-1111",
                    "launchPermission": {"add": {"items": [{"group": "all"}]}},
                },
                "responseElements": {"_return": True},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="AMI Not Made Public",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "ModifyImageAttribute",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "attributeType": "launchPermission",
                    "imageId": "ami-1111",
                    "launchPermission": {"add": {"items": [{"group": "not-all"}]}},
                },
                "responseElements": {"_return": True},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="AMI Launch Permissions Not Modified",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "ModifyImageAttribute",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "attributeType": "someThing",
                    "imageId": "ami-1111",
                    "someThing": {"add": {"items": [{"group": "all"}]}},
                },
                "responseElements": {"_return": True},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="AMI Added to User",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "1111",
                "eventName": "ModifyImageAttribute",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "attributeType": "launchPermission",
                    "imageId": "ami-1111",
                    "launchPermission": {"add": {"items": [{"userId": "bob"}]}},
                },
                "responseElements": {"_return": True},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Error Making AMI Public",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "errorCode": "UnauthorizedOperation",
                "eventID": "1111",
                "eventName": "ModifyImageAttribute",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2019-01-01T00:00:00Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.05",
                "recipientAccountId": "123456789012",
                "requestID": "1111",
                "requestParameters": {
                    "attributeType": "launchPermission",
                    "imageId": "ami-1111",
                    "launchPermission": {"add": {"items": [{"group": "all"}]}},
                },
                "responseElements": {"_return": True},
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla/2.0 (compatible; NEWT ActiveX; Win32)",
                "userIdentity": {
                    "accessKeyId": "1111",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                    "principalId": "1111",
                    "sessionContext": {
                        "attributes": {"creationDate": "2019-01-01T00:00:00Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/example-role",
                            "principalId": "1111",
                            "type": "Role",
                            "userName": "example-role",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
