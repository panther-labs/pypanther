from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get

awsrds_public_restore_tests: list[RuleTest] = [
    RuleTest(
        name="Not-Restore-RDS-Request",
        expected_result=False,
        log={
            "awsRegion": "us-east-1",
            "eventID": "797163d3-5726-441d-80a7-6eeb7464acd4",
            "eventName": "CreateDBInstance",
            "eventSource": "rds.amazonaws.com",
            "eventTime": "2018-07-30T22:14:06Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.04",
            "recipientAccountId": "123456789012",
            "requestID": "daf2e3f5-96a3-4df7-a026-863f96db793e",
            "requestParameters": {
                "allocatedStorage": 20,
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "enableCloudwatchLogsExports": ["audit", "error", "general", "slowquery"],
                "engine": "mysql",
                "masterUserPassword": "****",
                "masterUsername": "myawsuser",
            },
            "responseElements": {
                "allocatedStorage": 20,
                "autoMinorVersionUpgrade": True,
                "backupRetentionPeriod": 1,
                "cACertificateIdentifier": "rds-ca-2015",
                "copyTagsToSnapshot": False,
                "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-instance",
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "dBInstanceStatus": "creating",
                "dBParameterGroups": [{"dBParameterGroupName": "default.mysql8.0", "parameterApplyStatus": "in-sync"}],
                "dBSecurityGroups": [],
                "dBSubnetGroup": {
                    "dBSubnetGroupDescription": "default",
                    "dBSubnetGroupName": "default",
                    "subnetGroupStatus": "Complete",
                    "subnets": [
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1b"},
                            "subnetIdentifier": "subnet-cbfff283",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1e"},
                            "subnetIdentifier": "subnet-d7c825e8",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1f"},
                            "subnetIdentifier": "subnet-6746046b",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1c"},
                            "subnetIdentifier": "subnet-bac383e0",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1d"},
                            "subnetIdentifier": "subnet-42599426",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1a"},
                            "subnetIdentifier": "subnet-da327bf6",
                            "subnetStatus": "Active",
                        },
                    ],
                    "vpcId": "vpc-136a4c6a",
                },
                "dbInstancePort": 0,
                "dbiResourceId": "db-ETDZIIXHEWY5N7GXVC4SH7H5IA",
                "domainMemberships": [],
                "engine": "mysql",
                "engineVersion": "8.0.28",
                "iAMDatabaseAuthenticationEnabled": False,
                "licenseModel": "general-public-license",
                "masterUsername": "myawsuser",
                "monitoringInterval": 0,
                "multiAZ": False,
                "optionGroupMemberships": [{"optionGroupName": "default:mysql-8-0", "status": "in-sync"}],
                "pendingModifiedValues": {
                    "masterUserPassword": "****",
                    "pendingCloudwatchLogsExports": {"logTypesToEnable": ["audit", "error", "general", "slowquery"]},
                },
                "performanceInsightsEnabled": False,
                "preferredBackupWindow": "10:27-10:57",
                "preferredMaintenanceWindow": "sat:05:47-sat:06:17",
                "publiclyAccessible": True,
                "readReplicaDBInstanceIdentifiers": [],
                "storageEncrypted": False,
                "storageType": "standard",
                "vpcSecurityGroups": [{"status": "active", "vpcSecurityGroupId": "sg-f839b688"}],
            },
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "aws-cli/1.15.42 Python/3.6.1 Darwin/17.7.0 botocore/1.10.42",
            "userIdentity": {
                "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/johndoe",
                "principalId": "AKIAIOSFODNN7EXAMPLE",
                "type": "IAMUser",
                "userName": "johndoe",
            },
        },
    ),
    RuleTest(
        name="RDS-Restore-Not-Public",
        expected_result=False,
        log={
            "awsRegion": "us-east-1",
            "eventID": "797163d3-5726-441d-80a7-6eeb7464acd4",
            "eventName": "RestoreDBInstanceFromDBSnapshot",
            "eventSource": "rds.amazonaws.com",
            "eventTime": "2018-07-30T22:14:06Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.04",
            "recipientAccountId": "123456789012",
            "requestID": "daf2e3f5-96a3-4df7-a026-863f96db793e",
            "requestParameters": {
                "allocatedStorage": 20,
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "enableCloudwatchLogsExports": ["audit", "error", "general", "slowquery"],
                "engine": "mysql",
                "masterUserPassword": "****",
                "masterUsername": "myawsuser",
            },
            "responseElements": {
                "allocatedStorage": 20,
                "autoMinorVersionUpgrade": True,
                "backupRetentionPeriod": 1,
                "cACertificateIdentifier": "rds-ca-2015",
                "copyTagsToSnapshot": False,
                "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-instance",
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "dBInstanceStatus": "creating",
                "dBParameterGroups": [{"dBParameterGroupName": "default.mysql8.0", "parameterApplyStatus": "in-sync"}],
                "dBSecurityGroups": [],
                "dBSubnetGroup": {
                    "dBSubnetGroupDescription": "default",
                    "dBSubnetGroupName": "default",
                    "subnetGroupStatus": "Complete",
                    "subnets": [
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1b"},
                            "subnetIdentifier": "subnet-cbfff283",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1e"},
                            "subnetIdentifier": "subnet-d7c825e8",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1f"},
                            "subnetIdentifier": "subnet-6746046b",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1c"},
                            "subnetIdentifier": "subnet-bac383e0",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1d"},
                            "subnetIdentifier": "subnet-42599426",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1a"},
                            "subnetIdentifier": "subnet-da327bf6",
                            "subnetStatus": "Active",
                        },
                    ],
                    "vpcId": "vpc-136a4c6a",
                },
                "dbInstancePort": 0,
                "dbiResourceId": "db-ETDZIIXHEWY5N7GXVC4SH7H5IA",
                "domainMemberships": [],
                "engine": "mysql",
                "engineVersion": "8.0.28",
                "iAMDatabaseAuthenticationEnabled": False,
                "licenseModel": "general-public-license",
                "masterUsername": "myawsuser",
                "monitoringInterval": 0,
                "multiAZ": False,
                "optionGroupMemberships": [{"optionGroupName": "default:mysql-8-0", "status": "in-sync"}],
                "pendingModifiedValues": {
                    "masterUserPassword": "****",
                    "pendingCloudwatchLogsExports": {"logTypesToEnable": ["audit", "error", "general", "slowquery"]},
                },
                "performanceInsightsEnabled": False,
                "preferredBackupWindow": "10:27-10:57",
                "preferredMaintenanceWindow": "sat:05:47-sat:06:17",
                "publiclyAccessible": False,
                "readReplicaDBInstanceIdentifiers": [],
                "storageEncrypted": False,
                "storageType": "standard",
                "vpcSecurityGroups": [{"status": "active", "vpcSecurityGroupId": "sg-f839b688"}],
            },
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "aws-cli/1.15.42 Python/3.6.1 Darwin/17.7.0 botocore/1.10.42",
            "userIdentity": {
                "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/johndoe",
                "principalId": "AKIAIOSFODNN7EXAMPLE",
                "type": "IAMUser",
                "userName": "johndoe",
            },
        },
    ),
    RuleTest(
        name="RDS-Restore-Public",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventID": "797163d3-5726-441d-80a7-6eeb7464acd4",
            "eventName": "RestoreDBInstanceFromDBSnapshot",
            "eventSource": "rds.amazonaws.com",
            "eventTime": "2018-07-30T22:14:06Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.04",
            "recipientAccountId": "123456789012",
            "requestID": "daf2e3f5-96a3-4df7-a026-863f96db793e",
            "requestParameters": {
                "allocatedStorage": 20,
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "enableCloudwatchLogsExports": ["audit", "error", "general", "slowquery"],
                "engine": "mysql",
                "masterUserPassword": "****",
                "masterUsername": "myawsuser",
            },
            "responseElements": {
                "allocatedStorage": 20,
                "autoMinorVersionUpgrade": True,
                "backupRetentionPeriod": 1,
                "cACertificateIdentifier": "rds-ca-2015",
                "copyTagsToSnapshot": False,
                "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-instance",
                "dBInstanceClass": "db.m1.small",
                "dBInstanceIdentifier": "test-instance",
                "dBInstanceStatus": "creating",
                "dBParameterGroups": [{"dBParameterGroupName": "default.mysql8.0", "parameterApplyStatus": "in-sync"}],
                "dBSecurityGroups": [],
                "dBSubnetGroup": {
                    "dBSubnetGroupDescription": "default",
                    "dBSubnetGroupName": "default",
                    "subnetGroupStatus": "Complete",
                    "subnets": [
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1b"},
                            "subnetIdentifier": "subnet-cbfff283",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1e"},
                            "subnetIdentifier": "subnet-d7c825e8",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1f"},
                            "subnetIdentifier": "subnet-6746046b",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1c"},
                            "subnetIdentifier": "subnet-bac383e0",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1d"},
                            "subnetIdentifier": "subnet-42599426",
                            "subnetStatus": "Active",
                        },
                        {
                            "subnetAvailabilityZone": {"name": "us-east-1a"},
                            "subnetIdentifier": "subnet-da327bf6",
                            "subnetStatus": "Active",
                        },
                    ],
                    "vpcId": "vpc-136a4c6a",
                },
                "dbInstancePort": 0,
                "dbiResourceId": "db-ETDZIIXHEWY5N7GXVC4SH7H5IA",
                "domainMemberships": [],
                "engine": "mysql",
                "engineVersion": "8.0.28",
                "iAMDatabaseAuthenticationEnabled": False,
                "licenseModel": "general-public-license",
                "masterUsername": "myawsuser",
                "monitoringInterval": 0,
                "multiAZ": False,
                "optionGroupMemberships": [{"optionGroupName": "default:mysql-8-0", "status": "in-sync"}],
                "pendingModifiedValues": {
                    "masterUserPassword": "****",
                    "pendingCloudwatchLogsExports": {"logTypesToEnable": ["audit", "error", "general", "slowquery"]},
                },
                "performanceInsightsEnabled": False,
                "preferredBackupWindow": "10:27-10:57",
                "preferredMaintenanceWindow": "sat:05:47-sat:06:17",
                "publiclyAccessible": True,
                "readReplicaDBInstanceIdentifiers": [],
                "storageEncrypted": False,
                "storageType": "standard",
                "vpcSecurityGroups": [{"status": "active", "vpcSecurityGroupId": "sg-f839b688"}],
            },
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "aws-cli/1.15.42 Python/3.6.1 Darwin/17.7.0 botocore/1.10.42",
            "userIdentity": {
                "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/johndoe",
                "principalId": "AKIAIOSFODNN7EXAMPLE",
                "type": "IAMUser",
                "userName": "johndoe",
            },
        },
    ),
]


@panther_managed
class AWSRDSPublicRestore(Rule):
    default_description = (
        "Detects the recovery of a new public database instance from a snapshot. It may be part of data exfiltration."
    )
    display_name = "AWS Public RDS Restore"
    reports = {"MITRE ATT&CK": ["TA0010:T1020"]}
    default_reference = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html"
    default_severity = Severity.HIGH
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.RDS.PublicRestore-prototype"
    tests = awsrds_public_restore_tests

    def rule(self, event):
        if (
            event.get("eventSource", "") == "rds.amazonaws.com"
            and event.get("eventName", "") == "RestoreDBInstanceFromDBSnapshot"
        ):
            if deep_get(event, "responseElements", "publiclyAccessible"):
                return True
        return False

    def title(self, event):
        return f"Publicly Accessible RDS restore created in [{event.get('recipientAccountId', '')}]"

    def alert_context(self, event):
        return aws_rule_context(event)
