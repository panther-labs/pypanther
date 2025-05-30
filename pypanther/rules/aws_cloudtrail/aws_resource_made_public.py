import json

from policyuniverse.policy import Policy

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context
from pypanther.helpers.base import deep_get


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
    # Check if a policy (string or JSON) allows resource accessibility via the Internet
    # pylint: disable=too-complex

    def policy_is_internet_accessible(self, policy):
        """
        Check if a policy (string or JSON) allows resource accessibility via the Internet.

        Args:
        ----
        policy: A policy object that can be either a string or a JSON object

        Returns:
        -------
        bool: True if the policy allows internet access, False otherwise

        """
        # Handle empty policies (None, empty strings, empty dicts, etc.)
        if not policy:
            return False
        # Handle string policies by converting to JSON
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                return False
        # Check if the policy has a wildcard principal but also has organization ID restrictions
        # which should not be considered internet accessible
        policy_obj = Policy(policy)
        # If policyuniverse thinks it's not internet accessible, trust that
        if not policy_obj.is_internet_accessible():
            return False
        # For policies with multiple statements, we need to check each statement individually
        # If ANY statement is truly internet accessible, the policy is internet accessible
        has_internet_accessible_statement = False
        for statement in policy_obj.statements:
            if statement.effect != "Allow" or "*" not in statement.principals:
                continue
            # Check if there are organization ID conditions which restrict access
            has_org_condition = False
            for condition in statement.condition_entries:
                if condition.category == "organization":
                    has_org_condition = True
                    break
            # If this statement has a wildcard principal but no organization ID restrictions,
            # it's truly internet accessible
            if not has_org_condition:
                has_internet_accessible_statement = True
                break
        return has_internet_accessible_statement

    def rule(self, event):
        if not aws_cloudtrail_success(event):
            return False
        parameters = event.get("requestParameters", {})
        # Ignore events that are missing request params
        if not parameters:
            return False
        event_name = event.get("eventName", "")
        # Special case for SNS topic attributes that need additional attribute name check
        if event_name == "SetTopicAttributes" and parameters.get("attributeName", "") == "Policy":
            policy_value = parameters.get("attributeValue", {})
            return self.policy_is_internet_accessible(policy_value)
        # Map of event names to policy locations in parameters
        # S3
        # ECR
        # Elasticsearch
        # KMS
        # S3 Glacier
        # SNS & SQS
        # SecretsManager
        policy_location_map = {
            "PutBucketPolicy": lambda p: p.get("bucketPolicy", {}),
            "SetRepositoryPolicy": lambda p: p.get("policyText", {}),
            "CreateElasticsearchDomain": lambda p: p.get("accessPolicies", {}),
            "UpdateElasticsearchDomainConfig": lambda p: p.get("accessPolicies", {}),
            "CreateKey": lambda p: p.get("policy", {}),
            "PutKeyPolicy": lambda p: p.get("policy", {}),
            "SetVaultAccessPolicy": lambda p: deep_get(p, "policy", "policy", default={}),
            "SetQueueAttributes": lambda p: deep_get(p, "attributes", "Policy", default={}),
            "CreateTopic": lambda p: deep_get(p, "attributes", "Policy", default={}),
            "PutResourcePolicy": lambda p: p.get("resourcePolicy", {}),
        }
        # Get the policy extraction function for this event name
        policy_extractor = policy_location_map.get(event_name)
        if not policy_extractor:
            return False
        # Extract the policy using the appropriate function
        policy = policy_extractor(parameters)
        return self.policy_is_internet_accessible(policy)

    def title(self, event):
        # TODO(): Update this rule to use data models
        user = event.deep_get("userIdentity", "userName") or event.deep_get(
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

    tests = [
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
        RuleTest(
            name="Invalid JSON Policy (Should Not Alert)",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-01",
                "eventName": "PutBucketPolicy",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {"bucketPolicy": "invalid-json-policy"},
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="Multiple Conditions All Restrictive (Should Not Alert)",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-02",
                "eventName": "PutResourcePolicy",
                "eventSource": "secretsmanager.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {
                    "resourcePolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:PrincipalOrgID": "o-test123456",
                                        "aws:SourceVpc": "vpc-12345678",
                                    },
                                    "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                                },
                            },
                        ],
                    },
                },
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="Public Finding Keywords (Should Alert)",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-03",
                "eventName": "CreateElasticsearchDomain",
                "eventSource": "es.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {
                    "accessPolicies": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "es:*",
                                "Resource": "*",
                                "Sid": "PublicInternetAccess",
                            },
                        ],
                    },
                },
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="Wildcard Principal No Conditions (Should Alert)",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-04",
                "eventName": "PutKeyPolicy",
                "eventSource": "kms.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}],
                    },
                },
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="Mixed Conditions Some Restrictive (Should Alert)",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-05",
                "eventName": "SetQueueAttributes",
                "eventSource": "sqs.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {
                    "attributes": {
                        "Policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "sqs:*",
                                    "Resource": "*",
                                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-test123456"}},
                                },
                                {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"},
                            ],
                        },
                    },
                },
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="All Restrictive Conditions Types (Should Not Alert)",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "test-06",
                "eventName": "PutBucketPolicy",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2024-01-01 00:00:00.000",
                "eventType": "AwsApiCall",
                "requestParameters": {
                    "bucketPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "s3:GetObject",
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {"aws:PrincipalOrgID": "o-test123456"},
                                    "StringLike": {"aws:SourceVpc": "vpc-*"},
                                    "IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]},
                                },
                            },
                        ],
                    },
                },
                "userIdentity": {"type": "AssumedRole", "userName": "TestRole"},
            },
        ),
        RuleTest(
            name="Secrets Manager Restricted Access (Should Not Alert)",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "eventName": "PutResourcePolicy",
                "eventSource": "secretsmanager.amazonaws.com",
                "eventTime": "2025-03-05 19:48:47.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "requestParameters": {
                    "blockPublicPolicy": True,
                    "resourcePolicy": '{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Principal": "*",\n    "Action": "secretsmanager:GetSecretValue",\n    "Resource": "arn:aws:secretsmanager:us-west-2:123456789012:secret:paloma/example-secret-xxxxxx",\n    "Condition": {\n      "StringEquals": {\n        "aws:PrincipalOrgID": "o-xxxxxxxxxx"\n      },\n      "ForAnyValue:StringLike": {\n        "aws:PrincipalArn": ["arn:aws:iam::*:role/ExampleDeploymentRole*", "arn:aws:iam::*:role/ExampleCodeBuild-*"]\n      }\n    }\n  }, \n  {\n    "Effect": "Allow",\n    "Principal": "*",\n    "Action": "secretsmanager:GetSecretValue",\n    "Resource": "arn:aws:secretsmanager:us-west-2:123456789012:secret:paloma/example-secret-xxxxxx",\n    "Condition": {\n      "StringEquals": {\n        "aws:PrincipalOrgID": "o-xxxxxxxxxx"\n      },\n      "ForAnyValue:StringLike": {\n        "aws:PrincipalArn": ["arn:aws:iam::*:role/ExampleDeploymentRole*", "arn:aws:iam::*:role/ExampleCodeBuild-*"]\n      }\n    }\n  },\n  {\n    "Effect": "Allow",\n    "Principal": {\n      "AWS": ["arn:aws:iam::123456789012:role/ExampleRoleAssumption1", "arn:aws:iam::123456789012:role/ExampleRoleAssumption2"]\n    },\n    "Action": ["secretsmanager:Get*", "secretsmanager:Describe*", "secretsmanager:List*"],\n    "Resource": "arn:aws:secretsmanager:us-west-2:123456789012:secret:paloma/example-secret-xxxxxx"\n  }]\n}',
                    "secretId": "arn:aws:secretsmanager:us-west-2:123456789012:secret:paloma/example-secret-xxxxxx",
                },
                "responseElements": {
                    "arn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:paloma/example-secret-xxxxxx",
                    "name": "paloma/example-secret",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "10.0.0.1",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "secretsmanager.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "EXAMPLEACCESSKEYID",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx/example.user",
                    "principalId": "AROAXXXXXXXXXXXXXXXXX:example.user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-03-05T19:41:35Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx",
                            "principalId": "AROAXXXXXXXXXXXXXXXXX",
                            "type": "Role",
                            "userName": "AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="KMS Key Restricted Access (Should Not Alert)",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "eventName": "PutKeyPolicy",
                "eventSource": "kms.amazonaws.com",
                "eventTime": "2025-03-05 21:19:44.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "requestParameters": {
                    "bypassPolicyLockoutSafetyCheck": False,
                    "keyId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "policy": '{\n    "Version": "2008-10-17",\n    "Statement": [\n        {\n            "Effect": "Allow",\n            "Principal": {\n                "AWS": "arn:aws:iam::123456789012:root"\n            },\n            "Action": "kms:*",\n            "Resource": "*"\n        },\n        {\n            "Effect": "Allow",\n            "Principal": {\n                "AWS": [\n                    "arn:aws:iam::123456789012:role/ExampleRoleAssumption1",\n                    "arn:aws:iam::123456789012:role/ExampleRoleAssumption2"\n                ]\n            },\n            "Action": [\n                "kms:Decrypt",\n                "kms:DescribeKey"\n            ],\n            "Resource": "*"\n        },\n        {\n            "Effect": "Allow",\n            "Principal": "*",\n            "Action": "kms:Decrypt",\n            "Resource": "*",\n            "Condition": {\n                "StringEquals": {\n                    "aws:PrincipalOrgID": "o-xxxxxxxxxx"\n                },\n                "ForAnyValue:StringLike": {\n                    "aws:PrincipalArn": [\n                        "arn:aws:iam::*:role/ExampleDeploymentRole*",\n                        "arn:aws:iam::*:role/ExampleCodeBuild-*"\n                    ]\n                }\n            }\n        },\n        {\n            "Effect": "Allow",\n            "Principal": "*",\n            "Action": "kms:Decrypt",\n            "Resource": "*",\n            "Condition": {\n                "StringEquals": {\n                    "aws:PrincipalOrgID": "o-yyyyyyyyyy"\n                },\n                "ForAnyValue:StringLike": {\n                    "aws:PrincipalArn": [\n                        "arn:aws:iam::*:role/ExampleDeploymentRole*",\n                        "arn:aws:sts::*:role/ExampleCodeBuild-*",\n                        "arn:aws:sts::*:assumed-role/ExampleDeploymentRole*",\n                        "arn:aws:sts::*:assumed-role/ExampleCodeBuild-*"\n                    ]\n                }\n            }\n        }\n    ]\n}',
                    "policyName": "default",
                },
                "resources": [
                    {
                        "accountId": "123456789012",
                        "arn": "arn:aws:kms:us-west-2:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "type": "AWS::KMS::Key",
                    },
                ],
                "responseElements": {
                    "keyId": "arn:aws:kms:us-west-2:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "10.0.0.1",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_256_GCM_SHA384",
                    "clientProvidedHostHeader": "kms.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "EXAMPLEACCESSKEYID",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx/example.user",
                    "principalId": "AROAXXXXXXXXXXXXXXXXX:example.user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-03-05T21:15:00Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx",
                            "principalId": "AROAXXXXXXXXXXXXXXXXX",
                            "type": "Role",
                            "userName": "AWSReservedSSO_ExampleRole_xxxxxxxxxxxxxxxx",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
