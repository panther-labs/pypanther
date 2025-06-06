from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import pattern_match


@panther_managed
class AWSMacieEvasion(Rule):
    id = "AWS.Macie.Evasion-prototype"
    display_name = "AWS Macie Disabled/Updated"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.MEDIUM
    default_description = "Amazon Macie is a data security and data privacy service to discover and protect sensitive data. Security teams use Macie to detect open S3 Buckets that could have potentially sensitive data in it along with policy violations, such as missing Encryption. If an attacker disables Macie, it could potentially hide data exfiltration.\n"
    default_reference = "https://aws.amazon.com/macie/"
    default_runbook = "Analyze the events to ensure it's not normal maintenance. If it's abnormal, run the Indicator Search on the UserIdentity:Arn for the past hour and analyze other services accessed/changed.\n"
    threshold = 5
    summary_attributes = [
        "awsRegion",
        "eventName",
        "p_any_aws_arns",
        "p_any_ip_addresses",
        "userIdentity:type",
        "userIdentity:arn",
    ]
    MACIE_EVENTS = {
        "ArchiveFindings",
        "CreateFindingsFilter",
        "DeleteMember",
        "DisassociateFromMasterAccount",
        "DisassociateMember",
        "DisableMacie",
        "DisableOrganizationAdminAccount",
        "UpdateFindingsFilter",
        "UpdateMacieSession",
        "UpdateMemberSession",
        "UpdateClassificationJob",
    }

    def rule(self, event):
        return event.get("eventName") in self.MACIE_EVENTS and pattern_match(
            event.get("eventSource"),
            "macie*.amazonaws.com",
        )

    def title(self, event):
        account = event.get("recipientAccountId")
        user_arn = event.deep_get("userIdentity", "arn")
        return f"AWS Macie in AWS Account [{account}] Disabled/Updated by [{user_arn}]"

    tests = [
        RuleTest(
            name="ListMembers",
            expected_result=False,
            log={
                "awsRegion": "us-west-1",
                "eventCategory": "Management",
                "eventID": "5b3e4cf6-c37d-4c8c-9016-b8444a37ceaa",
                "eventName": "ListMembers",
                "eventSource": "macie2.amazonaws.com",
                "eventTime": "2022-09-27 18:11:33",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789012"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789012:role/Admin",
                    "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                ],
                "p_any_ip_addresses": ["178.253.78.209"],
                "p_any_trace_ids": ["AAAASSSST64ZTHFY7777"],
                "p_event_time": "2022-09-27 18:11:33",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-27 18:16:43.428",
                "p_row_id": "665d45a409cad7d68ff7bbd4138d02",
                "p_source_id": "b00eb354-da7a-49dd-9cc6-32535e32096a",
                "p_source_label": "CloudTrail Test",
                "readOnly": True,
                "recipientAccountId": "123456789012",
                "requestID": "2164bbea-3eb0-444b-8e10-8ba53b3460b6",
                "requestParameters": {"maxResults": "1", "onlyAssociated": "true"},
                "sourceIPAddress": "178.253.78.209",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "AAAASSSST64ZTHFY7777",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                    "principalId": "AAAAA44444LE6DYFKKKKK:Jack",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-27T17:56:01Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/Admin",
                            "principalId": "AAAAA44444LE6DYFKKKKK",
                            "type": "Role",
                            "userName": "Admin",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="UpdateSession",
            expected_result=True,
            log={
                "awsRegion": "us-east-2",
                "eventCategory": "Management",
                "eventID": "63033dfd-08c9-42f3-80ae-dca45e86ae84",
                "eventName": "UpdateMacieSession",
                "eventSource": "macie2.amazonaws.com",
                "eventTime": "2022-09-27 19:59:08",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789012"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789012:role/Admin",
                    "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                ],
                "p_any_ip_addresses": ["46.91.25.204"],
                "p_any_trace_ids": ["ASIASWJRT64Z42HFV6QX"],
                "p_event_time": "2022-09-27 19:59:08",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-27 20:02:43.816",
                "p_row_id": "665d45a409cad7d68ff7bbd4138123",
                "p_source_id": "b00eb354-da7a-49dd-9cc6-32535e32096a",
                "p_source_label": "CloudTrail Test",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1b9981dc-21d2-4f77-92b0-69e23c8a40de",
                "requestParameters": {"findingPublishingFrequency": "SIX_HOURS"},
                "sourceIPAddress": "46.91.25.204",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIASWJRT64Z42HFV6QX",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                    "principalId": "AAAAA44444LE6DYFKKKKK:Jack",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-27T17:56:01Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/Admin",
                            "principalId": "AAAAA44444LE6DYFKKKKK",
                            "type": "Role",
                            "userName": "Admin",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="UpdateSession (Macie v1 event)",
            expected_result=True,
            log={
                "awsRegion": "us-east-2",
                "eventCategory": "Management",
                "eventID": "63033dfd-08c9-42f3-80ae-dca45e86ae84",
                "eventName": "UpdateMacieSession",
                "eventSource": "macie.amazonaws.com",
                "eventTime": "2022-09-27 19:59:08",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789012"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789012:role/Admin",
                    "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                ],
                "p_any_ip_addresses": ["46.91.25.204"],
                "p_any_trace_ids": ["ASIASWJRT64Z42HFV6QX"],
                "p_event_time": "2022-09-27 19:59:08",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-27 20:02:43.816",
                "p_row_id": "665d45a409cad7d68ff7bbd4138123",
                "p_source_id": "b00eb354-da7a-49dd-9cc6-32535e32096a",
                "p_source_label": "CloudTrail Test",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "requestID": "1b9981dc-21d2-4f77-92b0-69e23c8a40de",
                "requestParameters": {"findingPublishingFrequency": "SIX_HOURS"},
                "sourceIPAddress": "46.91.25.204",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                "userIdentity": {
                    "accessKeyId": "ASIASWJRT64Z42HFV6QX",
                    "accountId": "123456789012",
                    "arn": "arn:aws:sts::123456789012:assumed-role/Admin/Jack",
                    "principalId": "AAAAA44444LE6DYFKKKKK:Jack",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-27T17:56:01Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789012",
                            "arn": "arn:aws:iam::123456789012:role/Admin",
                            "principalId": "AAAAA44444LE6DYFKKKKK",
                            "type": "Role",
                            "userName": "Admin",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
