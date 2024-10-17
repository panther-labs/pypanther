from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, lookup_aws_account_name


@panther_managed
class AWSRootActivity(Rule):
    id = "AWS.Root.Activity-prototype"
    display_name = "Root Account Activity"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Identity & Access Management", "DemoThreatHunting", "Privilege Escalation:Valid Accounts"]
    reports = {"CIS": ["3.3"], "MITRE ATT&CK": ["TA0004:T1078"]}
    default_severity = Severity.HIGH
    default_description = "Root account activity was detected.\n"
    default_runbook = "Investigate the usage of the root account. If this root activity was not authorized, immediately change the root credentials and investigate what actions the root account took.\n"
    default_reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
    summary_attributes = [
        "awsRegion",
        "eventName",
        "eventSource",
        "userAgent",
        "p_any_aws_account_ids",
        "p_any_aws_arns",
        "p_any_ip_addresses",
    ]
    EVENT_ALLOW_LIST = {"CreateServiceLinkedRole"}

    def rule(self, event):
        return (
            event.deep_get("userIdentity", "type") == "Root"
            and aws_cloudtrail_success(event)
            and (event.deep_get("userIdentity", "invokedBy") is None)
            and (event.get("eventType") != "AwsServiceEvent")
            and (event.get("eventName") not in self.EVENT_ALLOW_LIST)
        )

    def dedup(self, event):
        return (
            event.get("sourceIPAddress", "<UNKNOWN_IP>")
            + ":"
            + lookup_aws_account_name(event.get("recipientAccountId"))
            + ":"
            + str(event.get("readOnly"))
        )

    def title(self, event):
        return f"AWS root user activity [{event.get('eventName')}] in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"

    def alert_context(self, event):
        return {
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userIdentityAccountId": event.deep_get("userIdentity", "accountId"),
            "userIdentityArn": event.deep_get("userIdentity", "arn"),
            "eventTime": event.get("eventTime"),
            "mfaUsed": event.deep_get("additionalEventData", "MFAUsed"),
        }

    def severity(self, event):
        if event.get("readOnly"):
            return "LOW"
        return "HIGH"

    tests = [
        RuleTest(
            name="Root Activity - CreateServiceLinkedRole",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "CreateServiceLinkedRole",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": {
                    "bucketName": "bucket",
                    "versioning": [""],
                    "host": ["bucket.s3.us-west-2.amazonaws.com"],
                    "VersioningConfiguration": {
                        "Status": "Enabled",
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                        "MfaDelete": "Enabled",
                    },
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "AuthenticationMethod": "AuthHeader",
                },
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Root Activity",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketVersioning",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": {
                    "bucketName": "bucket",
                    "versioning": [""],
                    "host": ["bucket.s3.us-west-2.amazonaws.com"],
                    "VersioningConfiguration": {
                        "Status": "Enabled",
                        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
                        "MfaDelete": "Enabled",
                    },
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "AuthenticationMethod": "AuthHeader",
                },
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="IAMUser Activity",
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
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-01-01T00:00:00Z"},
                    },
                    "invokedBy": "signin.amazonaws.com",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetBucketAcl",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "signin.amazonaws.com",
                "requestParameters": {
                    "host": ["bucket.s3.us-west-2.amazonaws.com"],
                    "bucketName": "bucket",
                    "acl": [""],
                },
                "responseElements": None,
                "additionalEventData": {
                    "SignatureVersion": "SigV4",
                    "CipherSuite": "ECDHE-RSA-AES128-SHA",
                    "AuthenticationMethod": "AuthHeader",
                    "vpcEndpointId": "vpce-1",
                },
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "vpcEndpointId": "vpce-1",
            },
        ),
        RuleTest(
            name="Root User Failed Activity",
            expected_result=False,
            log={
                "awsRegion": "redacted",
                "errorMessage": "Not a valid response for the provided request id: aws_ccV60redacted",
                "eventID": "redacted",
                "eventName": "ExternalIdPDirectoryLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "redacted",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.05",
                "p_alert_creation_time": "redacted",
                "p_alert_id": "redacted",
                "p_alert_update_time": "redacted",
                "p_any_aws_account_ids": ["redacted"],
                "p_any_aws_arns": [],
                "p_any_ip_addresses": ["redacted"],
                "p_event_time": "redacted",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "redacted",
                "p_row_id": "redacted",
                "p_rule_error": None,
                "p_rule_id": "AWS.Root.Activity",
                "p_rule_reports": {"CIS": ["3.3"]},
                "p_rule_tags": ["AWS", "Identity & Access Management"],
                "p_source_id": "redacted",
                "p_source_label": "CloudTrail",
                "readOnly": False,
                "recipientAccountId": "redacted",
                "requestID": "redacted",
                "responseElements": {"ExternalIdPDirectoryLogin": "Failure"},
                "sourceIPAddress": "redacted",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "",
                    "accountId": "redacted",
                    "arn": "",
                    "principalId": "redacted",
                    "type": "Root",
                },
            },
        ),
        RuleTest(
            name="Successful Root Login",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:root",
                    "accountId": "123456789012",
                    "userName": "root",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
