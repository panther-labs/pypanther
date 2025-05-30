from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailAttemptToLeaveOrg(Rule):
    id = "AWS.CloudTrail.AttemptToLeaveOrg-prototype"
    display_name = "AWS CloudTrail Attempt To Leave Org"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008", "TA0005:T1666"]}
    default_description = "Detects when an actor attempts to remove an AWS account from an Organization. Security configurations are often defined at the organizational level. Leaving the organization can disrupt or totally shut down these controls.\n"
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.organizations-leave/\n"
    )
    default_runbook = "Determine if the attempt was successful. Monitor and potentially suspect the user account which  attempted the action. Determine if the root account is compromised.\n"
    summary_attributes = ["p_any_ip_addresses", "p_any_aws_account_ids"]
    tags = [
        "AWS CloudTrail",
        "Defense Evasion",
        "Impair Defenses",
        "Disable or Modify Cloud Logs",
        "Modify Cloud Resource Hierarchy",
        "Beta",
    ]

    def rule(self, event: PantherEvent) -> bool:
        return event.get("eventName") == "LeaveOrganization"

    def title(self, event: PantherEvent) -> str:
        account_name = lookup_aws_account_name(event.get("recipientAccountId"))
        actor = event.udm("actor_user")
        # Return a more informative message if the attempt was unsuccessful
        if not aws_cloudtrail_success(event):
            return f"Failed attempt to remove {account_name} from your AWS organization by {actor}"
        return f"Account {account_name} has been removed from your AWS organization by {actor}"

    def severity(self, event: PantherEvent) -> str:
        # Downgrade to HIGH if attempt is unsuccessful
        if not aws_cloudtrail_success(event):
            return "HIGH"
        return "DEFAULT"

    def alert_context(self, event: PantherEvent) -> dict:
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Failed Attempt to Leave Org",
            expected_result=True,
            log={
                "p_event_time": "2025-01-20 15:59:33.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-20 16:05:54.322564138",
                "awsRegion": "us-east-1",
                "errorCode": "AccessDenied",
                "errorMessage": "User: arn:aws:sts::111122223333:assumed-role/SampleRole/SampleSession is not authorized to perform: organizations:LeaveOrganization on resource: * because no identity-based policy allows the organizations:LeaveOrganization action",
                "eventCategory": "Management",
                "eventID": "f52c1358-4ddb-4453-a676-3f4dbc64d713",
                "eventName": "LeaveOrganization",
                "eventSource": "organizations.amazonaws.com",
                "eventTime": "2025-01-20 15:59:33.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "67dce4b9-c7d1-4c91-a686-d34bbd5365eb",
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/SampleSession",
                    "principalId": "SAMPLE_PRINCIPAL_ID:SampleSession",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-20T15:59:30Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/SampleRole",
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
