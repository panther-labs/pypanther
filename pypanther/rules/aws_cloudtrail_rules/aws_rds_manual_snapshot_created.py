from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.log_types import LogType

awsrds_manual_snapshot_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Manual Snapshot Created",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROA2DFDF0C1FDFCAD2B2:fake.user",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/fake.user",
                "accountId": "123456789012",
                "accessKeyId": "ASIAFFA5AFEC02FFCD8ED",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROA2DFDF0C1FDFCAD2B2",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "accountId": "123456789012",
                        "userName": "ARole",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": "2023-12-08T13:53:48Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": "2023-12-08T14:55:19Z",
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBSnapshot",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) 68319f60-9dec-43b2-9702-de3a08c9d8a3 HashiCorp-terraform-exec/0.17.3",
            "requestParameters": {
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "dBSnapshotIdentifier": "exfiltration",
            },
            "responseElements": {
                "allocatedStorage": 10,
                "instanceCreateTime": "Dec 8, 2023 2:55:17 PM",
                "dBSnapshotIdentifier": "exfiltration",
                "dbiResourceId": "db-TYZSSMTWIABIR6QKKFGI55XKJQ",
                "port": 3306,
                "availabilityZone": "us-west-2b",
                "dBSnapshotArn": "arn:aws:rds:us-west-2:123456789012:snapshot:exfiltration",
                "processorFeatures": [],
                "encrypted": False,
                "percentProgress": 0,
                "optionGroupName": "default:mysql-8-0",
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "storageType": "gp2",
                "iAMDatabaseAuthenticationEnabled": False,
                "vpcId": "vpc-0c9c141888d129377",
                "storageThroughput": 0,
                "dedicatedLogVolume": False,
                "status": "creating",
                "masterUsername": "admin",
                "engine": "mysql",
                "snapshotType": "manual",
                "engineVersion": "8.0.33",
                "licenseModel": "general-public-license",
                "snapshotTarget": "region",
            },
            "requestID": "e5fd8d41-db7c-45df-a21a-f9cff8c19755",
            "eventID": "c665b42c-89b4-4072-ad71-0f9c8d50f649",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "rds.us-west-2.amazonaws.com",
            },
        },
    ),
    PantherRuleTest(
        Name="Public Snapshot Created",
        ExpectedResult=True,
        Log={
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROA2DFDF0C1FDFCAD2B2:fake.user",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/fake.user",
                "accountId": "123456789012",
                "accessKeyId": "ASIAFFA5AFEC02FFCD8ED",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROA2DFDF0C1FDFCAD2B2",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "accountId": "123456789012",
                        "userName": "ARole",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": "2023-12-08T13:53:48Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": "2023-12-08T14:55:19Z",
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBSnapshot",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) 68319f60-9dec-43b2-9702-de3a08c9d8a3 HashiCorp-terraform-exec/0.17.3",
            "requestParameters": {
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "dBSnapshotIdentifier": "exfiltration",
            },
            "responseElements": {
                "allocatedStorage": 10,
                "instanceCreateTime": "Dec 8, 2023 2:55:17 PM",
                "dBSnapshotIdentifier": "exfiltration",
                "dbiResourceId": "db-TYZSSMTWIABIR6QKKFGI55XKJQ",
                "port": 3306,
                "availabilityZone": "us-west-2b",
                "dBSnapshotArn": "arn:aws:rds:us-west-2:123456789012:snapshot:exfiltration",
                "processorFeatures": [],
                "encrypted": False,
                "percentProgress": 0,
                "optionGroupName": "default:mysql-8-0",
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "storageType": "gp2",
                "iAMDatabaseAuthenticationEnabled": False,
                "vpcId": "vpc-0c9c141888d129377",
                "storageThroughput": 0,
                "dedicatedLogVolume": False,
                "status": "creating",
                "masterUsername": "admin",
                "engine": "mysql",
                "snapshotType": "public",
                "engineVersion": "8.0.33",
                "licenseModel": "general-public-license",
                "snapshotTarget": "region",
            },
            "requestID": "e5fd8d41-db7c-45df-a21a-f9cff8c19755",
            "eventID": "c665b42c-89b4-4072-ad71-0f9c8d50f649",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "rds.us-west-2.amazonaws.com",
            },
        },
    ),
    PantherRuleTest(
        Name="Automated Snapshot Created",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROA2DFDF0C1FDFCAD2B2:fake.user",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/fake.user",
                "accountId": "123456789012",
                "accessKeyId": "ASIAFFA5AFEC02FFCD8ED",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROA2DFDF0C1FDFCAD2B2",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "accountId": "123456789012",
                        "userName": "ARole",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": "2023-12-08T13:53:48Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": "2023-12-08T14:55:19Z",
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBSnapshot",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) 68319f60-9dec-43b2-9702-de3a08c9d8a3 HashiCorp-terraform-exec/0.17.3",
            "requestParameters": {
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "dBSnapshotIdentifier": "exfiltration",
            },
            "responseElements": {
                "allocatedStorage": 10,
                "instanceCreateTime": "Dec 8, 2023 2:55:17 PM",
                "dBSnapshotIdentifier": "exfiltration",
                "dbiResourceId": "db-TYZSSMTWIABIR6QKKFGI55XKJQ",
                "port": 3306,
                "availabilityZone": "us-west-2b",
                "dBSnapshotArn": "arn:aws:rds:us-west-2:123456789012:snapshot:exfiltration",
                "processorFeatures": [],
                "encrypted": False,
                "percentProgress": 0,
                "optionGroupName": "default:mysql-8-0",
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "storageType": "gp2",
                "iAMDatabaseAuthenticationEnabled": False,
                "vpcId": "vpc-0c9c141888d129377",
                "storageThroughput": 0,
                "dedicatedLogVolume": False,
                "status": "creating",
                "masterUsername": "admin",
                "engine": "mysql",
                "snapshotType": "automated",
                "engineVersion": "8.0.33",
                "licenseModel": "general-public-license",
                "snapshotTarget": "region",
            },
            "requestID": "e5fd8d41-db7c-45df-a21a-f9cff8c19755",
            "eventID": "c665b42c-89b4-4072-ad71-0f9c8d50f649",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "rds.us-west-2.amazonaws.com",
            },
        },
    ),
    PantherRuleTest(
        Name="Awsbackup Snapshot Created",
        ExpectedResult=False,
        Log={
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROA2DFDF0C1FDFCAD2B2:fake.user",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/fake.user",
                "accountId": "123456789012",
                "accessKeyId": "ASIAFFA5AFEC02FFCD8ED",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROA2DFDF0C1FDFCAD2B2",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "accountId": "123456789012",
                        "userName": "ARole",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": "2023-12-08T13:53:48Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": "2023-12-08T14:55:19Z",
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBSnapshot",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; darwin; arm64) 68319f60-9dec-43b2-9702-de3a08c9d8a3 HashiCorp-terraform-exec/0.17.3",
            "requestParameters": {
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "dBSnapshotIdentifier": "exfiltration",
            },
            "responseElements": {
                "allocatedStorage": 10,
                "instanceCreateTime": "Dec 8, 2023 2:55:17 PM",
                "dBSnapshotIdentifier": "exfiltration",
                "dbiResourceId": "db-TYZSSMTWIABIR6QKKFGI55XKJQ",
                "port": 3306,
                "availabilityZone": "us-west-2b",
                "dBSnapshotArn": "arn:aws:rds:us-west-2:123456789012:snapshot:exfiltration",
                "processorFeatures": [],
                "encrypted": False,
                "percentProgress": 0,
                "optionGroupName": "default:mysql-8-0",
                "dBInstanceIdentifier": "terraform-20231208145149286600000001",
                "storageType": "gp2",
                "iAMDatabaseAuthenticationEnabled": False,
                "vpcId": "vpc-0c9c141888d129377",
                "storageThroughput": 0,
                "dedicatedLogVolume": False,
                "status": "creating",
                "masterUsername": "admin",
                "engine": "mysql",
                "snapshotType": "awsbackup",
                "engineVersion": "8.0.33",
                "licenseModel": "general-public-license",
                "snapshotTarget": "region",
            },
            "requestID": "e5fd8d41-db7c-45df-a21a-f9cff8c19755",
            "eventID": "c665b42c-89b4-4072-ad71-0f9c8d50f649",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "rds.us-west-2.amazonaws.com",
            },
        },
    ),
]


class AWSRDSManualSnapshotCreated(PantherRule):
    RuleID = "AWS.RDS.ManualSnapshotCreated-prototype"
    DisplayName = "AWS RDS Manual/Public Snapshot Created"
    LogTypes = [LogType.AWS_CloudTrail]
    Tags = ["AWS", "Exfiltration", "Transfer Data to Cloud Account"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    Severity = PantherSeverity.Low
    Description = "A manual snapshot of an RDS database was created. An attacker may use this to exfiltrate the DB contents to another account; use this as a correlation rule.\n"
    Runbook = "Ensure the snapshot was shared with an allowed AWS account. If not, delete the snapshot and quarantine the compromised IAM user.\n"
    Reference = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateSnapshot.html"
    SummaryAttributes = ["eventSource", "recipientAccountId", "awsRegion", "p_any_aws_arns"]
    Tests = awsrds_manual_snapshot_created_tests

    def rule(self, event):
        return all(
            [
                event.get("eventSource", "") == "rds.amazonaws.com",
                event.get("eventName", "") == "CreateDBSnapshot",
                event.deep_get("responseElements", "snapshotType") in {"manual", "public"},
            ]
        )

    def title(self, event):
        account_id = event.get("recipientAccountId", "")
        rds_instance_id = event.deep_get("responseElements", "dBInstanceIdentifier")
        return f"Manual RDS Snapshot Created in [{account_id}] for RDS instance [{rds_instance_id}]"

    def alert_context(self, event):
        return aws_rule_context(event)
