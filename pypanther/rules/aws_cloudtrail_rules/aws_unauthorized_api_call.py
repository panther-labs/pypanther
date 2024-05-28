from ipaddress import ip_address
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

aws_cloud_trail_unauthorized_api_call_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Unauthorized API Call from Within AWS (IP)",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    }
                },
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
    PantherRuleTest(
        Name="Unauthorized API Call from Within AWS (FQDN)",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    }
                },
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
    PantherRuleTest(
        Name="Authorized API Call",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "1111",
                "arn": "arn:aws:iam::123456789012:user/tester",
                "accountId": "123456789012",
                "accessKeyId": "1",
                "userName": "tester",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2019-01-01T00:00:00Z",
                    }
                },
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


class AWSCloudTrailUnauthorizedAPICall(PantherRule):
    RuleID = "AWS.CloudTrail.UnauthorizedAPICall-prototype"
    DisplayName = "Monitor Unauthorized API Calls"
    DedupPeriodMinutes = 1440
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Discovery:Cloud Service Discovery"]
    Reports = {"CIS": ["3.1"], "MITRE ATT&CK": ["TA0007:T1526"]}
    Severity = PantherSeverity.Info
    Description = "An unauthorized AWS API call was made"
    Runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-unauthorized-api-call"
    Reference = "https://amzn.to/3aOukaA"
    SummaryAttributes = [
        "eventName",
        "userAgent",
        "sourceIpAddress",
        "recipientAccountId",
        "p_any_aws_arns",
    ]
    Threshold = 20
    Tests = aws_cloud_trail_unauthorized_api_call_tests
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
        return (
            event.get("errorCode") == "AccessDenied"
            and event.get("eventName") not in self.EVENT_EXCEPTIONS
        )

    def dedup(self, event):
        return deep_get(event, "userIdentity", "principalId", default="<UNKNOWN_PRINCIPAL>")

    def title(self, event):
        return f"Access denied to {deep_get(event, 'userIdentity', 'type')} [{self.dedup(event)}]"

    def alert_context(self, event):
        return aws_rule_context(event)
