from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_unused_region_tests: list[RuleTest] = [
    RuleTest(
        name="Authorized region",
        expected_result=False,
        log={
            "awsRegion": "us-west-2",
            "eventID": "1111",
            "eventName": "StartQueryExecution",
            "eventSource": "athena.amazonaws.com",
            "eventTime": "2021-10-19 04:50:27",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "clientRequestToken": "1111",
                "queryExecutionContext": {"database": "1111"},
                "queryString": "-- Query 2 different time windows for comparison, return sources that have events over the past time window but not within the current time window.\n-- Past time windows: 2 hours\n-- Current time window: 1 hour\n\nWITH PastCount as\n(\nselect p_source_label, count(*)  as PastTotal\nfrom panther_views.all_logs \nWHERE p_parse_time >= current_timestamp - interval '7200' second\n    and partition_time >= to_unixtime(date_trunc('HOUR', current_timestamp - interval '7200' second))\n    group by p_source_label\n),\nCurrentCount as \n(\nselect  p_source_label, count(*)  as CurrentTotal\nfrom panther_views.all_logs \nWHERE p_parse_time >= current_timestamp - interval '3600' second\n    and partition_time >= to_unixtime(date_trunc('HOUR', current_timestamp - interval '3600' second))\n    group by p_source_label\n)\nSELECT PastCount.*, coalesce(CurrentCount.CurrentTotal, 0) AS CurrentTotal \nFROM CurrentCount \nRIGHT OUTER JOIN PastCount ON PastCount.p_source_label = CurrentCount.p_source_label\nWHERE CurrentTotal IS NULL",
                "resultConfiguration": {},
                "workGroup": "Panther",
            },
            "responseElements": {"queryExecutionId": "fc62d701-d474-46a4-b6cf-de6bafdbdb3c"},
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "aws-sdk-go/1.38.37 (go1.16; linux; amd64) exec-env/AWS_Lambda_go1.x",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                "principalId": "1111",
                "sessionContext": {
                    "attributes": {"creationDate": "2021-10-19T04:01:27Z", "mfaAuthenticated": "false"},
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
        name="Unauthorized region, read-only",
        expected_result=False,
        log={
            "awsRegion": "ap-east-1",
            "eventID": "1111",
            "eventName": "Decrypt",
            "eventSource": "kms.amazonaws.com",
            "eventTime": "2021-10-19 00:56:05",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "encryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "encryptionContext": {"aws:s3:arn": "arn:aws:s3:::1111"},
            },
            "resources": [
                {
                    "accountId": "123456789012",
                    "arn": "arn:aws:kms:us-west-2:123456789012:key/1111",
                    "type": "AWS::KMS::Key",
                },
            ],
            "sourceIPAddress": "AWS Internal",
            "userAgent": "AWS Internal",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                "principalId": "1111",
                "sessionContext": {
                    "attributes": {"creationDate": "2021-10-19T00:31:41Z", "mfaAuthenticated": "false"},
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
        name="Unauthorized region",
        expected_result=True,
        log={
            "apiVersion": "20140328",
            "awsRegion": "eu-central-1",
            "eventID": "1111",
            "eventName": "CreateLogStream",
            "eventSource": "logs.amazonaws.com",
            "eventTime": "2021-10-21 22:29:06",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "requestID": "1111",
            "requestParameters": {
                "logGroupName": "/aws/lambda/panther-analysis-api",
                "logStreamName": "2021/10/21/[$LATEST]1111",
            },
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "awslambda-worker/1.0 rusoto/0.47.0 rust/1.55.0 linux",
            "userIdentity": {
                "accessKeyId": "1111",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/example-role/example-user",
                "principalId": "1111",
                "sessionContext": {
                    "attributes": {"creationDate": "2021-10-21T22:29:02Z", "mfaAuthenticated": "false"},
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


@panther_managed
class AWSUnusedRegion(Rule):
    id = "AWS.UnusedRegion-prototype"
    display_name = "Unused AWS Region"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Defense Evasion:Unused/Unsupported Cloud Regions", "Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0005:T1535"]}
    default_severity = Severity.HIGH
    default_description = "CloudTrail logged non-read activity from a verboten AWS region."
    default_runbook = (
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws-enable-disable-regions.html"
    )
    default_reference = "https://attack.mitre.org/techniques/T1535/"
    summary_attributes = ["eventSource", "eventName", "recipientAccountId", "awsRegion", "p_any_aws_arns"]
    tests = aws_unused_region_tests
    # Define a list of verboten or unused regions
    # Could modify to include expected user mappings: { "123456789012": { "us-west-1", "us-east-2" } }
    UNUSED_REGIONS = {"ap-east-1", "eu-west-3", "eu-central-1"}

    def rule(self, event):
        if event.get("awsRegion", "<UNKNOWN_AWS_REGION>") in self.UNUSED_REGIONS and event.get("readOnly") is False:
            return True
        return False

    def title(self, event):
        aws_username = deep_get(event, "userIdentity", "sessionContext", "sessionIssuer", "userName")
        return f"Non-read-only API call in unused region {event.get('awsRegion', '<UNKNOWN_AWS_REGION>')} by user {aws_username}"

    def alert_context(self, event):
        return aws_rule_context(event)
