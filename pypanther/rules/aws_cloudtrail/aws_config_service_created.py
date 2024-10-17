from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSConfigServiceCreated(Rule):
    id = "AWS.ConfigService.Created-prototype"
    display_name = "AWS Config Service Created"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Discovery:Cloud Service Discovery"]
    reports = {"CIS": ["3.9"], "MITRE ATT&CK": ["TA0007:T1526"]}
    default_severity = Severity.INFO
    default_description = "An AWS Config Recorder or Delivery Channel was created\n"
    default_runbook = "Verify that the Config Service changes were authorized. If not, revert them and investigate who caused the change. Consider altering permissions to prevent this from happening again in the future.\n"
    default_reference = "https://aws.amazon.com/config/"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # API calls that are indicative of an AWS Config Service change
    CONFIG_SERVICE_CREATE_EVENTS = {"PutDeliveryChannel", "PutConfigurationRecorder", "StartConfigurationRecorder"}

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.CONFIG_SERVICE_CREATE_EVENTS

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Config Recorder Delivery Channel Created",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "tester",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "config.amazonaws.com",
                "eventName": "PutDeliveryChannel",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"configurationRecorderName": "default"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Config Recorder Deleted",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "tester",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "config.amazonaws.com",
                "eventName": "DeleteDeliveryChannel",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"configurationRecorderName": "default"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Error Creating Config Recorder Delivery Channel",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "errorCode": "InvalidDeliveryChannelNameException",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "tester",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "config.amazonaws.com",
                "eventName": "PutDeliveryChannel",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {"configurationRecorderName": "default"},
                "responseElements": None,
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
