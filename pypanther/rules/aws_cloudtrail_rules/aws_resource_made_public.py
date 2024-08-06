import json

from policyuniverse.policy import Policy

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.helpers.panther_default import aws_cloudtrail_success

aws_cloud_trail_resource_made_public_tests: list[RuleTest] = [
    RuleTest(
        name="ECR Made Public",
        expected_result=True,
        log={
            "awsRegion": "eu-west-1",
            "eventID": "685e066d-a3aa-4323-a6a1-2f187a2fc986",
            "eventName": "SetRepositoryPolicy",
            "eventSource": "ecr.amazonaws.com",
            "eventTime": "2020-11-20 06:19:05.000",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "112233445566",
            "requestID": "95fd6392-627c-467b-b940-895183d3298d",
            "requestParameters": {
                "force": False,
                "policyText": '{"Version":"2012-10-17","Statement":[{"Action":["ecr:BatchCheckLayerAvailability","ecr:BatchGetImage","ecr:GetAuthorizationToken","ecr:GetDownloadUrlForLayer"],"Effect":"Allow","Principal":"*","Sid":"PublicRead"}]}',
                "repositoryName": "community",
            },
            "resources": [
                {"accountId": "112233445566", "arn": "arn:aws:ecr:eu-west-1:112233445566:repository/community"},
            ],
            "responseElements": {
                "policyText": '{\n  "Version" : "2012-10-17",\n  "Statement" : [ {\n    "Sid" : "PublicRead",\n    "Effect" : "Allow",\n    "Principal" : "*",\n    "Action" : [ "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:GetDownloadUrlForLayer" ]\n  } ]\n}',
                "registryId": "112233445566",
                "repositoryName": "community",
            },
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAIJJG73VC6IW5OFVQ",
                "accountId": "112233445566",
                "arn": "arn:aws:sts::112233445566:assumed-role/ServiceRole/AWSCloudFormation",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAJJJJTTTT44445IJJJ:AWSCloudFormation",
                "sessionContext": {
                    "attributes": {"creationDate": "2020-11-20T06:19:04Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "112233445566",
                        "arn": "arn:aws:iam::112233445566:role/ServiceRole",
                        "principalId": "AROAJJJJTTTT44445IJJJ",
                        "type": "Role",
                        "userName": "ServiceRole",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
            "p_event_time": "2020-11-20 06:19:05.000",
            "p_parse_time": "2020-11-20 06:31:53.258",
            "p_log_type": "AWS.CloudTrail",
            "p_row_id": "ea68a92f0295a6bed49fa8af068faa05",
            "p_any_aws_account_ids": ["112233445566"],
            "p_any_aws_arns": [
                "arn:aws:ecr:eu-west-1:112233445566:repository/community",
                "arn:aws:iam::112233445566:role/ServiceRole",
                "arn:aws:sts::112233445566:assumed-role/ServiceRole/AWSCloudFormation",
            ],
        },
    ),
    RuleTest(
        name="S3 Made Publicly Accessible",
        expected_result=True,
        log={
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": "ECDHE-RSA-AES128-SHA",
                "SignatureVersion": "SigV4",
                "vpcEndpointId": "vpce-1111",
            },
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "PutBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "bucketName": "example-bucket",
                "bucketPolicy": {
                    "Statement": [
                        {
                            "Action": "s3:GetBucketAcl",
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Resource": "arn:aws:s3:::example-bucket",
                            "Sid": "Public Access",
                        },
                    ],
                    "Version": "2012-10-17",
                },
                "host": ["s3.us-west-2.amazonaws.com"],
                "policy": [""],
            },
            "responseElements": None,
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
                },
                "type": "AssumedRole",
            },
            "vpcEndpointId": "vpce-1111",
        },
    ),
    RuleTest(
        name="S3 Not Made Publicly Accessible",
        expected_result=False,
        log={
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": "ECDHE-RSA-AES128-SHA",
                "SignatureVersion": "SigV4",
                "vpcEndpointId": "vpce-1111",
            },
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "PutBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "bucketName": "example-bucket",
                "bucketPolicy": {
                    "Statement": [
                        {
                            "Action": "s3:GetBucketAcl",
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudtrail.amazonaws.com"},
                            "Resource": "arn:aws:s3:::example-bucket",
                            "Sid": "Public Access",
                        },
                    ],
                    "Version": "2012-10-17",
                },
                "host": ["s3.us-west-2.amazonaws.com"],
                "policy": [""],
            },
            "responseElements": None,
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
                },
                "type": "AssumedRole",
            },
            "vpcEndpointId": "vpce-1111",
        },
    ),
    RuleTest(
        name="Null Request Parameters",
        expected_result=False,
        log={
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": "ECDHE-RSA-AES128-SHA",
                "SignatureVersion": "SigV4",
                "vpcEndpointId": "vpce-1111",
            },
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "PutBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": None,
            "responseElements": None,
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
                },
                "type": "AssumedRole",
            },
            "vpcEndpointId": "vpce-1111",
        },
    ),
    RuleTest(
        name="S3 Failed to make Publicly Accessible",
        expected_result=False,
        log={
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": "ECDHE-RSA-AES128-SHA",
                "SignatureVersion": "SigV4",
                "vpcEndpointId": "vpce-1111",
            },
            "errorCode": "AccessDenied",
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "PutBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "bucketName": "example-bucket",
                "bucketPolicy": {
                    "Statement": [
                        {
                            "Action": "s3:GetBucketAcl",
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Resource": "arn:aws:s3:::example-bucket",
                            "Sid": "Public Access",
                        },
                    ],
                    "Version": "2012-10-17",
                },
                "host": ["s3.us-west-2.amazonaws.com"],
                "policy": [""],
            },
            "responseElements": None,
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
                },
                "type": "AssumedRole",
            },
            "vpcEndpointId": "vpce-1111",
        },
    ),
    RuleTest(
        name="Empty Policy Payload",
        expected_result=False,
        log={
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": "ECDHE-RSA-AES128-SHA",
                "SignatureVersion": "SigV4",
                "vpcEndpointId": "vpce-1111",
            },
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "SetQueueAttributes",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2019-01-01T00:00:00Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "attributes": {"Policy": ""},
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/example-queue",
            },
            "responseElements": None,
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
                },
                "type": "AssumedRole",
            },
            "vpcEndpointId": "vpce-1111",
        },
    ),
]


@panther_managed
class AWSCloudTrailResourceMadePublic(Rule):
    id = "AWS.CloudTrail.ResourceMadePublic-prototype"
    display_name = "AWS Resource Made Public"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Exfiltration:Transfer Data to Cloud Account"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    default_description = "Some AWS resource was made publicly accessible over the internet. Checks ECR, Elasticsearch, KMS, S3, S3 Glacier, SNS, SQS, and Secrets Manager.\n"
    default_runbook = "Adjust the policy so that the resource is no longer publicly accessible"
    default_reference = "https://aws.amazon.com/blogs/security/identifying-publicly-accessible-resources-with-amazon-vpc-network-access-analyzer/"
    summary_attributes = ["userAgent", "sourceIpAddress", "vpcEndpointId", "recipientAccountId", "p_any_aws_arns"]
    tests = aws_cloud_trail_resource_made_public_tests
    # Check that the IAM policy allows resource accessibility via the Internet
    # Normally this check helps avoid overly complex functions that are doing too many things,
    # but in this case we explicitly want to handle 10 different cases in 10 different ways.
    # Any solution that avoids too many return statements only increases the complexity of this rule.
    # pylint: disable=too-many-return-statements, too-complex

    def policy_is_internet_accessible(self, json_policy):
        if json_policy is None:
            return False
        return Policy(json_policy).is_internet_accessible()

    def rule(self, event):
        if not aws_cloudtrail_success(event):
            return False
        parameters = event.get("requestParameters", {})
        # Ignore events that are missing request params
        if not parameters:
            return False
        policy = ""
        # S3
        if event["eventName"] == "PutBucketPolicy":
            return self.policy_is_internet_accessible(parameters.get("bucketPolicy"))
        # ECR
        if event["eventName"] == "SetRepositoryPolicy":
            policy = parameters.get("policyText", {})
        # Elasticsearch
        if event["eventName"] in ["CreateElasticsearchDomain", "UpdateElasticsearchDomainConfig"]:
            policy = parameters.get("accessPolicies", {})
        # KMS
        if event["eventName"] in ["CreateKey", "PutKeyPolicy"]:
            policy = parameters.get("policy", {})
        # S3 Glacier
        if event["eventName"] == "SetVaultAccessPolicy":
            policy = deep_get(parameters, "policy", "policy", default={})
        # SNS & SQS
        if event["eventName"] in ["SetQueueAttributes", "CreateTopic"]:
            policy = deep_get(parameters, "attributes", "Policy", default={})
        # SNS
        if event["eventName"] == "SetTopicAttributes" and parameters.get("attributeName", "") == "Policy":
            policy = parameters.get("attributeValue", {})
        # SecretsManager
        if event["eventName"] == "PutResourcePolicy":
            policy = parameters.get("resourcePolicy", {})
        if not policy:
            return False
        return self.policy_is_internet_accessible(json.loads(policy))

    def title(self, event):
        # TODO(): Update this rule to use data models
        user = deep_get(event, "userIdentity", "userName") or deep_get(
            event,
            "userIdentity",
            "sessionContext",
            "sessionIssuer",
            "userName",
            default="<MISSING_USER>",
        )
        if event.get("Resources"):
            return f"Resource {event.get('Resources')[0].get('arn', 'MISSING')} made public by {user}"
        return f"{event.get('eventSource', 'MISSING SOURCE')} resource made public by {user}"

    def alert_context(self, event):
        return aws_rule_context(event)
