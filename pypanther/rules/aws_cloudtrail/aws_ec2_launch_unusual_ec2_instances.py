from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSEC2LaunchUnusualEC2Instances(Rule):
    id = "AWS.EC2.LaunchUnusualEC2Instances-prototype"
    display_name = "AWS EC2 Launch Unusual EC2 Instances"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0002:T1610"]}
    default_description = (
        "Detect when an actor deploys an EC2 instance with an unusual profile based on your business needs.\n"
    )
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-launch-unusual-instances/\n"
    )
    default_runbook = "Follow up with the instance to identify whether the instance has a legitimate purpose. Reach out to the actor to ensure they performed the action.\n"
    summary_attributes = [
        "p_any_aws_account_ids",
        "p_any_instance_ids",
        "p_any_arns",
        "p_any_aws_tags",
        "p_any_usernames",
    ]
    tags = ["CloudTrail", "EC2", "Execution", "Deploy Container", "Execution:Deploy Container"]
    # Configuration Required
    #   Add/remove items from the set below as needed. It should contain instance types which aren't
    #   expected to be used in your environment
    # Large GPU compute, but no graphics - could be used for crypt mining
    UNUSUAL_INSTANCE_TYPES = {"p2.xlarge"}

    def rule(self, event: PantherEvent) -> bool:
        instance_type = event.deep_get("requestParameters", "instanceType")
        return all(
            (
                event.get("eventName") == "RunInstances",
                event.get("eventSource") == "ec2.amazonaws.com",
                instance_type in self.get_unusual_instance_types(),
            ),
        )

    def title(self, event: PantherEvent) -> str:
        # The actor in these events is always AutoScalingService
        account = lookup_aws_account_name(event.get("recipientAccountId"))
        instance_type = event.deep_get("requestParameters", "instanceType")
        return f"EC2 instance with a suspicious type '{instance_type}' was launched in in {account}"

    def severity(self, event: PantherEvent) -> str:
        if not aws_cloudtrail_success(event):
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["instanceType"] = event.deep_get("requestParameters", "instanceType")
        return context

    def get_unusual_instance_types(self) -> bool:
        # Making this a separate function allows us to mock it during unit tests for reliable testing!
        return self.UNUSUAL_INSTANCE_TYPES

    tests = [
        RuleTest(
            name="Successful Unusual EC2",
            expected_result=True,
            mocks=[RuleMock(object_name="get_unusual_instance_types", return_value="p2.xlarge")],
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "41fab871-150b-43ad-b42a-39fff3f2ca4e",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2024-12-16 18:41:07.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "95cdbe4d-8ff7-4111-8f08-44f510371035",
                "requestParameters": {
                    "availabilityZone": "us-west-2a",
                    "blockDeviceMapping": {},
                    "clientToken": "fleet-180da986-0bb4-c936-0c9a-0e20a0c6d1aa-0",
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "instanceType": "p2.xlarge",
                    "instancesSet": {"items": [{"maxCount": 1, "minCount": 1}]},
                    "monitoring": {"enabled": False},
                    "subnetId": "subnet-083e5906ef2809ac2",
                },
                "responseElements": {
                    "groupSet": {},
                    "instancesSet": {
                        "items": [
                            {
                                "amiLaunchIndex": 0,
                                "architecture": "arm64",
                                "blockDeviceMapping": {},
                                "bootMode": "uefi",
                                "capacityReservationSpecification": {"capacityReservationPreference": "open"},
                                "clientToken": "fleet-180da986-0bb4-c936-0c9a-0e20a0c6d1aa-0",
                                "cpuOptions": {"coreCount": 2, "threadsPerCore": 1},
                                "currentInstanceBootMode": "uefi",
                                "ebsOptimized": False,
                                "enaSupport": True,
                                "enclaveOptions": {"enabled": False},
                                "groupSet": {"items": [{"groupId": "sg-03d704b35372e74e8", "groupName": "my-group"}]},
                                "hypervisor": "xen",
                                "iamInstanceProfile": {
                                    "arn": "arn:aws:iam::111122223333:instance-profile/profile-id",
                                    "id": "PROFILE_ID",
                                },
                                "imageId": "ami-013e7d3a6659f358d",
                                "instanceId": "i-07d06021b0da55115",
                                "instanceState": {"code": 0, "name": "pending"},
                                "instanceType": "p2.xlarge",
                                "launchTime": 1734374467000,
                                "maintenanceOptions": {"autoRecovery": "default"},
                                "metadataOptions": {
                                    "httpEndpoint": "enabled",
                                    "httpProtocolIpv4": "enabled",
                                    "httpProtocolIpv6": "disabled",
                                    "httpPutResponseHopLimit": 2,
                                    "httpTokens": "required",
                                    "instanceMetadataTags": "disabled",
                                    "state": "pending",
                                },
                                "monitoring": {"state": "disabled"},
                                "networkInterfaceSet": {
                                    "items": [
                                        {
                                            "attachment": {
                                                "attachTime": 1734374467000,
                                                "attachmentId": "eni-attach-022e4a3077e096442",
                                                "deleteOnTermination": True,
                                                "deviceIndex": 0,
                                                "networkCardIndex": 0,
                                                "status": "attaching",
                                            },
                                            "groupSet": {
                                                "items": [
                                                    {
                                                        "groupId": "sg-03d704b35372e74e8",
                                                        "groupName": "eks-cluster-sg-k8s-goat-cluster-816437967",
                                                    },
                                                ],
                                            },
                                            "interfaceType": "interface",
                                            "ipv6AddressesSet": {},
                                            "macAddress": "02:fc:9a:8a:db:c3",
                                            "networkInterfaceId": "eni-03ac9043f76fab96c",
                                            "operator": {"managed": False},
                                            "ownerId": "111122223333",
                                            "privateDnsName": "ip-192-168-1-95.us-west-2.compute.internal",
                                            "privateIpAddress": "192.168.1.95",
                                            "privateIpAddressesSet": {
                                                "item": [
                                                    {
                                                        "primary": True,
                                                        "privateDnsName": "ip-192-168-1-95.us-west-2.compute.internal",
                                                        "privateIpAddress": "192.168.1.95",
                                                    },
                                                ],
                                            },
                                            "sourceDestCheck": True,
                                            "status": "in-use",
                                            "subnetId": "subnet-083e5906ef2809ac2",
                                            "tagSet": {},
                                            "vpcId": "vpc-0330bfd33da75b36e",
                                        },
                                    ],
                                },
                                "operator": {"managed": False},
                                "placement": {"availabilityZone": "us-west-2a", "tenancy": "default"},
                                "privateDnsName": "ip-192-168-1-95.us-west-2.compute.internal",
                                "privateDnsNameOptions": {
                                    "enableResourceNameDnsAAAARecord": False,
                                    "enableResourceNameDnsARecord": False,
                                    "hostnameType": "ip-name",
                                },
                                "privateIpAddress": "192.168.1.95",
                                "productCodes": {},
                                "rootDeviceName": "/dev/xvda",
                                "rootDeviceType": "ebs",
                                "sourceDestCheck": True,
                                "stateReason": {"code": "pending", "message": "pending"},
                                "subnetId": "subnet-083e5906ef2809ac2",
                                "tagSet": {
                                    "items": [
                                        {"key": "k8s.io/cluster-autoscaler/enabled", "value": "true"},
                                        {
                                            "key": "aws:autoscaling:groupName",
                                            "value": "eks-ng-0ca246e9-cac9e862-bfd9-a821-c9fd-9916df5654eb",
                                        },
                                        {
                                            "key": "aws:ec2:fleet-id",
                                            "value": "fleet-180da986-0bb4-c936-0c9a-0e20a0c6d1aa",
                                        },
                                        {"key": "eks:cluster-name", "value": "k8s-goat-cluster"},
                                        {"key": "eks:nodegroup-name", "value": "ng-0ca246e9"},
                                        {"key": "alpha.eksctl.io/nodegroup-name", "value": "ng-0ca246e9"},
                                        {"key": "alpha.eksctl.io/nodegroup-type", "value": "managed"},
                                        {"key": "k8s.io/cluster-autoscaler/k8s-goat-cluster", "value": "owned"},
                                        {"key": "aws:ec2launchtemplate:id", "value": "lt-07a0b5cea4ece8ffd"},
                                        {"key": "aws:ec2launchtemplate:version", "value": "1"},
                                        {"key": "Name", "value": "k8s-goat-cluster-ng-0ca246e9-Node"},
                                        {"key": "kubernetes.io/cluster/k8s-goat-cluster", "value": "owned"},
                                    ],
                                },
                                "virtualizationType": "hvm",
                                "vpcId": "vpc-0330bfd33da75b36e",
                            },
                        ],
                    },
                    "ownerId": "111122223333",
                    "requestId": "95cdbe4d-8ff7-4111-8f08-44f510371035",
                    "requesterId": "414886084714",
                    "reservationId": "r-0ff0b006325a10345",
                },
                "sourceIPAddress": "autoscaling.amazonaws.com",
                "userAgent": "autoscaling.amazonaws.com",
                "userIdentity": {
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling",
                    "invokedBy": "autoscaling.amazonaws.com",
                    "principalId": "PRINCIPAL_ID:AutoScaling",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-12-16T18:41:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                            "principalId": "PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "AWSServiceRoleForAutoScaling",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Failed Unusual EC2",
            expected_result=True,
            mocks=[RuleMock(object_name="get_unusual_instance_types", return_value="p2.xlarge")],
            log={
                "awsRegion": "ca-south-3r",
                "errorCode": "Client.UnauthorizedOperation",
                "errorMessage": "You are not authorized to perform this operation. User: arn:aws:sts::751353041310:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000 is not authorized to perform: ec2:RunInstances on resource: arn:aws:ec2:ca-south-3r:751353041310:instance/* because no identity-based policy allows the ec2:RunInstances action. Encoded authorization failure message: T-kSWIRFn32_fxSgyNzoE36avE5lRaRniAjDs-OdhlNgyecEbeTN_dCroUmnEqAbDOrevkgWv8iyUzs0XJxEDlAcgDztlJ-QPNokwAE1JUrWPZcLqpsuM6kK46d5jCUvmzpU_Egq-fML4ed58JHxMdyU4Iz1WGOb6S3W3FB5jghu3JqyDR1B8S8qHryW-e8H1ukHarLt7Ogr4rvYezZ3sf_DNCPDjCGLOSI75x4W0X4Wcl9B9eAuhG-hRbB8KG3e-15CmtpWvw5brndvmrK0sAKwOdcyI47AXNV1DKVLKBNjxwNSQB4knWTX00TASAtGZYroYLyadRTdjZO_CwPGIkcI7wiuAPwSJTrri9xF8zPb5ZJ-Zt4-fQRZoge3sWBFv_wRNOcdGXu8MidJV1ev4CJOpwygM9bO68S_ueU2u_MvKE_zRYrMzTYSMiBKpZGZBDiIZGOGOSzJK8aZ5_F0g5CzhI0IzBxBQh2QFLF0eZe6prRdYEnOZ33EDlaD68PhuyM5xFYzNATqG8UlMtNG7eE1XCMpAmLRAv8ZSnE0PUMrg-Z7RhLyIb3p37VxzKKQHVTdEarNtE22jp38CJ0uRZy5eiNmu-O3JMLeB-AuSYFFoGPtH6h2dH2uV4Fj27vJ4...",
                "eventCategory": "Management",
                "eventID": "1a4debbb-12e9-4bde-b8c7-ea29002bb2a7",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2024-08-01T11:30:23Z",
                "eventType": "AwsApiCall",
                "eventVersion": "1.09",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "900138736586",
                "requestID": "b663854b-4ebf-4be3-8de0-9c5471904762",
                "requestParameters": {
                    "blockDeviceMapping": {},
                    "clientToken": "5dd59182-3917-421c-9b2c-7c92954b66ee",
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "instanceType": "p2.xlarge",
                    "instancesSet": {"items": [{"imageId": "ami-aCBbfd13bdb1d1E4b", "maxCount": 10, "minCount": 1}]},
                    "monitoring": {"enabled": False},
                    "subnetId": "subnet-0e540f0c7ffb48ae9",
                },
                "responseElements": None,
                "sourceIPAddress": "06.237.252.245",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2.ca-south-3r.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "stratus-red-team_c8ff220a-7e52-429b-868f-d979123ed2d3",
                "userIdentity": {
                    "accessKeyId": "ASIA9F6MXE9HSYOXYQOS",
                    "accountId": "900138736586",
                    "arn": "arn:aws:sts::900138736586:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000",
                    "principalId": "AROA13YEHY3VAS32TD341:aws-go-sdk-1722511821294449000",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-08-01T11:30:22Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "900138736586",
                            "arn": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
                            "principalId": "AROA13YEHY3VAS32TD341",
                            "type": "Role",
                            "userName": "stratus-red-team-ec2lui-role-idtzskbvtd",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
