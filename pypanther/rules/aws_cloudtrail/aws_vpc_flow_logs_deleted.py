from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSVPCFlowLogsDeleted(Rule):
    id = "AWS.VPCFlow.LogsDeleted-prototype"
    display_name = "AWS VPC Flow Logs Removed"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    default_description = "Detects when logs for a VPC have been removed."
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.vpc-remove-flow-logs/"
    default_runbook = "Look for an accompanying 'DeleteVpc' event, and confirm that they are related. if there is no matching VPC Deletion event, followup with the log removal to determine if it is legitimate."
    tags = [
        "AWS",
        "Cloudtrail",
        "Defense Evasion",
        "Impair Defenses",
        "Disable or Modify Cloud Logs",
        "Defense Evasion:Impair Defenses",
        "Security Control",
        "Beta",
    ]

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") == "DeleteFlowLogs"

    def title(self, event):
        account = event.deep_get("userIdentity", "accountId", default="<UNKNOWN ACCOUNT>")
        region = event.get("awsRegion", "<UNKNOWN REGION>")
        return f"VPC Flow logs have been deleted in {lookup_aws_account_name(account)} in {region}"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Logs Deleted",
            expected_result=True,
            log={
                "p_event_time": "2024-11-26 19:29:38.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-26 19:35:54.358700257",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "d5e6d49c-0be9-4c53-ab8a-c7ca86edd130",
                "eventName": "DeleteFlowLogs",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2024-11-26 19:29:38.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "1dcd7d36-72be-4aad-9e9d-93b88e0135ea",
                "requestParameters": {
                    "DeleteFlowLogsRequest": {"FlowLogId": {"content": "fl-0ef673ef70c4f07cc", "tag": 1}},
                },
                "responseElements": {
                    "DeleteFlowLogsResponse": {
                        "requestId": "1dcd7d36-72be-4aad-9e9d-93b88e0135ea",
                        "unsuccessful": "",
                        "xmlns": "http://ec2.amazonaws.com/doc/2016-11-15/",
                    },
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-26T17:05:50Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
