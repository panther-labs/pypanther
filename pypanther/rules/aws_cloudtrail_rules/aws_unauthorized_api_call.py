from ipaddress import ip_address

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

aws_cloud_trail_unauthorized_api_call_tests: list[RuleTest] = [
    RuleTest(
        name="Unauthorized API Call from Within AWS (IP)",
        expected_result=True,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateServiceLinkedRole",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "3.10.107.144",
            "errorCode": "AccessDenied",
            "errorMessage": "User: arn:aws:iam::123456789012:user/tester is not authorized to perform: iam:Action on resource: arn:aws:iam::123456789012:resource",
            "userAgent": "sqs.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Unauthorized API Call from Within AWS (FQDN)",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateServiceLinkedRole",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "sqs.amazonaws.com",
            "errorCode": "AccessDenied",
            "errorMessage": "User: arn:aws:iam::123456789012:user/tester is not authorized to perform: iam:Action on resource: arn:aws:iam::123456789012:resource",
            "userAgent": "sqs.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
    RuleTest(
        name="Authorized API Call",
        expected_result=False,
        log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"}},
                "invokedBy": "signin.amazonaws.com",
            },
            "eventTime": "2019-01-01T00:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateServiceLinkedRole",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "111.111.111.111",
            "userAgent": "signin.amazonaws.com",
            "requestParameters": None,
            "responseElements": None,
            "requestID": "1",
            "eventID": "1",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
    ),
]


@panther_managed
class AWSCloudTrailUnauthorizedAPICall(Rule):
    id = "AWS.CloudTrail.UnauthorizedAPICall-prototype"
    display_name = "Monitor Unauthorized API Calls"
    dedup_period_minutes = 1440
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Discovery:Cloud Service Discovery"]
    reports = {"CIS": ["3.1"], "MITRE ATT&CK": ["TA0007:T1526"]}
    default_severity = Severity.INFO
    default_description = "An unauthorized AWS API call was made"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-unauthorized-api-call"
    default_reference = "https://amzn.to/3aOukaA"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    threshold = 20
    tests = aws_cloud_trail_unauthorized_api_call_tests
    # Do not alert on these access denied errors for these events.
    # Events could be exceptions because they are particularly noisy and provide little to no value,
    # or because they are expected as part of the normal operating procedure for certain tools.
    # Noisy, doesn't really provide any actionable info
    # The audit role hits this when scanning locked down resources
    EVENT_EXCEPTIONS = {"DescribeEventAggregates", "ListResourceTags"}

    def rule(self, event):
        # Validate the request came from outside of AWS
        try:
            ip_address(event.get("sourceIPAddress"))
        except ValueError:
            return False
        return event.get("errorCode") == "AccessDenied" and event.get("eventName") not in self.EVENT_EXCEPTIONS

    def dedup(self, event):
        return deep_get(event, "userIdentity", "principalId", default="<UNKNOWN_PRINCIPAL>")

    def title(self, event):
        return f"Access denied to {deep_get(event, 'userIdentity', 'type')} [{self.dedup(event)}]"

    def alert_context(self, event):
        return aws_rule_context(event)
