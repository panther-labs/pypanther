from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailEventSelectorsDisabled(Rule):
    id = "AWS.CloudTrail.EventSelectorsDisabled-prototype"
    display_name = "CloudTrail Event Selectors Disabled"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["3.5"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.MEDIUM
    default_description = "A CloudTrail Trail was modified to exclude management events for 1 or more resource types.\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-cloudtrail-modified"
    default_reference = (
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-update-a-trail-console.html"
    )
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    # API calls that are indicative of CloudTrail changes
    CLOUDTRAIL_EDIT_SELECTORS = {"PutEventSelectors"}

    def rule(self, event):
        if not (aws_cloudtrail_success(event) and event.get("eventName") in self.CLOUDTRAIL_EDIT_SELECTORS):
            return False
        # Check if management events are included for each selector.
        #    deep_walk only returns a list if there's more than 1 entry in the nested array, so we must
        #    enforce it to be a list.
        includes = event.deep_walk("requestParameters", "eventSelectors", "includeManagementEvents")
        if includes is None:
            includes = []
        if not isinstance(includes, list):
            includes = [includes]
        # Return False all the management events are included, else return True and raise alert
        return not all(includes)

    def dedup(self, event):
        # Merge on the CloudTrail ARN
        return event.deep_get("requestParameters", "trailName", default="<UNKNOWN_NAME>")

    def title(self, event):
        return f"Management events have been exluded from CloudTrail [{self.dedup(event)}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Event Selector Disabled",
            expected_result=True,
            log={
                "p_event_time": "2024-11-25 17:51:21.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 17:55:54.253083422",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "4ca1cb25-7633-496b-8f92-6de876228c3f",
                "eventName": "PutEventSelectors",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2024-11-25 17:51:21.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "a8c6184a-89b1-4fc1-a6fa-324748d48b64",
                "requestParameters": {
                    "eventSelectors": [
                        {
                            "dataResources": [
                                {"type": "AWS::S3::Object", "values": []},
                                {"type": "AWS::Lambda::Function", "values": []},
                            ],
                            "excludeManagementEventSources": [],
                            "includeManagementEvents": False,
                            "readWriteType": "ReadOnly",
                        },
                    ],
                    "trailName": "sample-cloudtrail-name",
                },
                "responseElements": {
                    "eventSelectors": [
                        {
                            "dataResources": [
                                {"type": "AWS::S3::Object", "values": []},
                                {"type": "AWS::Lambda::Function", "values": []},
                            ],
                            "excludeManagementEventSources": [],
                            "includeManagementEvents": False,
                            "readWriteType": "ReadOnly",
                        },
                    ],
                    "trailARN": "arn:aws:cloudtrail:us-west-2:111122223333:trail/sample-cloudtrail-name",
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "cloudtrail.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "EXAMPLEPRINCIPLEID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "EXAMPLEPRINCIPLEID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Event Selector Enabled",
            expected_result=False,
            log={
                "p_event_time": "2024-11-25 17:51:21.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 17:55:54.253083422",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "4ca1cb25-7633-496b-8f92-6de876228c3f",
                "eventName": "PutEventSelectors",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2024-11-25 17:51:21.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "a8c6184a-89b1-4fc1-a6fa-324748d48b64",
                "requestParameters": {
                    "eventSelectors": [
                        {
                            "dataResources": [],
                            "excludeManagementEventSources": [],
                            "includeManagementEvents": True,
                            "readWriteType": "All",
                        },
                    ],
                    "trailName": "sample-cloudtrail-name",
                },
                "responseElements": {
                    "eventSelectors": [
                        {
                            "dataResources": [],
                            "excludeManagementEventSources": [],
                            "includeManagementEvents": True,
                            "readWriteType": "All",
                        },
                    ],
                    "trailARN": "arn:aws:cloudtrail:us-west-2:111122223333:trail/sample-cloudtrail-name",
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "cloudtrail.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "EXAMPLEPRINCIPLEID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "EXAMPLEPRINCIPLEID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Uninteresting Event Type",
            expected_result=False,
            log={
                "p_event_time": "2024-11-25 17:50:24.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-25 17:55:54.172592534",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "63fb143a-c494-4510-8e9e-34172e4872c3",
                "eventName": "GetEventSelectors",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": "2024-11-25 17:50:24.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "cad6aff4-1558-49c5-ae4a-c512058751f1",
                "requestParameters": {"trailName": "sample-cloudtrail-name"},
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "cloudtrail.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) stratus-red-team_83c9a458-ffab-4d43-8b02-9691311e8c0a HashiCorp-terraform-exec/0.17.3",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "EXAMPLEPRINCIPLEID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-25T16:53:42Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "EXAMPLEPRINCIPLEID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
