from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSEC2Monitoring(Rule):
    default_description = "Checks CloudTrail for occurrences of EC2 Image Actions."
    display_name = "AWS EC2 Image Monitoring"
    reports = {"MITRE ATT&CK": ["TA0002:T1204"]}
    default_runbook = "Verify that the action was not taken by a malicious actor."
    default_reference = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2imagebuilder.html#amazonec2imagebuilder-actions-as-permissions"
    default_severity = Severity.INFO
    tags = ["ec2"]
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.EC2.Monitoring-prototype"
    # AWS CloudTrail API eventNames for EC2 Image Actions
    EC2_IMAGE_ACTIONS = [
        "CopyFpgaImage",
        "CopyImage",
        "CreateFpgaImage",
        "CreateImage",
        "CreateRestoreImageTask",
        "CreateStoreImageTask",
        "ImportImage",
    ]

    def rule(self, event):
        # Disqualify any eventSource that is not ec2
        if event.get("eventSource", "") != "ec2.amazonaws.com":
            return False
        # Disqualify AWS Service-Service operations, which can appear in a variety of forms
        if (
            event.get("sourceIPAddress", "").endswith(".amazonaws.com")
            or event.deep_get("userIdentity", "type", default="") == "AWSService"
            or event.deep_get("userIdentity", "invokedBy", default="") == "AWS Internal"
            or event.deep_get("userIdentity", "invokedBy", default="").endswith(".amazonaws.com")
        ):
            # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
            #  events with ec2.amazonaws.com as the source name where users of the
            #  web-console will have their sourceIPAddress recorded as "AWS Internal"
            #  though their userIdentity will be more normal.
            #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
            return False
        # Dry run operations get logged as SES Internal in the sourceIPAddress
        #  but not in the invokedBy field
        if event.get("errorCode", "") == "Client.DryRunOperation":
            return False
        # Disqualify any eventNames that do not Include Image Actions
        # and events that have readOnly set to false
        if event.get("eventName", "") in self.EC2_IMAGE_ACTIONS:
            return True
        return False

    def title(self, event):
        return f"[{event.deep_get('userIdentity', 'sessionContext', 'sessionIssuer', 'userName')}] triggered a CloudTrail action [{event.get('eventName')}] within AWS Account ID: [{event.get('recipientAccountId')}]"

    tests = [
        RuleTest(
            name="CopyImage",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "0ea3f05a-066c-43f9-8869-393ba67e7936",
                "eventName": "CreateImage",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-09-29 22:25:17",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123456789101"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123456789101:role/DevAdministrator",
                    "arn:aws:sts::123456789101:assumed-role/DevAdministrator/test_user",
                ],
                "p_any_aws_instance_ids": ["i-0381a3817f72a949d"],
                "p_any_domain_names": ["AWS Internal"],
                "p_any_trace_ids": ["ASIA5PZQZ5QHE2FUNXHR"],
                "p_event_time": "2022-09-29 22:25:17",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-29 22:27:25.748",
                "p_row_id": "66011977ec1fd0cf9dacf7d913f08d06",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "CloudTrail Logs",
                "readOnly": False,
                "recipientAccountId": "123456789101",
                "requestID": "e686939a-a08a-4fd6-abf5-9ea34793cf25",
                "requestParameters": {
                    "blockDeviceMapping": {
                        "items": [{"deviceName": "/dev/xvda", "ebs": {"deleteOnTermination": True, "volumeSize": 8}}],
                    },
                    "instanceId": "i-0381a3817f72a949d",
                    "name": "testimage",
                    "noReboot": False,
                },
                "responseElements": {
                    "imageId": "ami-06aaf5e4b77161786",
                    "requestId": "e686939a-a08a-4fd6-abf5-9ea34793cf25",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIA5PZQZ5QHE2FUNXHR",
                    "accountId": "123456789101",
                    "arn": "arn:aws:sts::123456789101:assumed-role/DevAdministrator/test_user",
                    "principalId": "AROA5PZQZ5QHBULW27VAC:test_user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-29T22:22:46Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789101",
                            "arn": "arn:aws:iam::123456789101:role/DevAdministrator",
                            "principalId": "AROA5PZQZ5QHBULW27VAC",
                            "type": "Role",
                            "userName": "DevAdministrator",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="RunInstance",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "015c585b-cbc2-4f9e-9c52-a2f22f3c09f4",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-10-20 14:16:43",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123123123123"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123123123123:role/DevAdministrator",
                    "arn:aws:sts::123123123123:assumed-role/DevAdministrator/temp_user",
                ],
                "p_any_aws_instance_ids": ["i-0d7e4b9be8a0de6ea"],
                "p_any_aws_tags": ["Name:test2"],
                "p_any_domain_names": ["AWS Internal", "ip-111.111.111.111.ec2.internal"],
                "p_any_ip_addresses": ["111.111.111.111"],
                "p_any_trace_ids": ["ASIA5PZQZ5QHAW6RFPO5"],
                "p_any_usernames": ["DevAdministrator"],
                "p_event_time": "2022-10-20 14:16:43",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-10-20 14:21:06.845",
                "p_row_id": "be7b3bed9bb891e4a8b9f38d149909",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "Panther Identity Org CloudTrail",
                "readOnly": False,
                "recipientAccountId": "123123123123",
                "requestID": "25c95576-a825-44fd-971d-5a52c1e3b2be",
                "requestParameters": {
                    "blockDeviceMapping": {},
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "ebsOptimized": False,
                    "instanceType": "t1.micro",
                    "instancesSet": {
                        "items": [{"imageId": "ami-026b57f3c383c2eec", "keyName": "kp1", "maxCount": 1, "minCount": 1}],
                    },
                    "monitoring": {"enabled": False},
                    "networkInterfaceSet": {
                        "items": [
                            {
                                "associatePublicIpAddress": True,
                                "deviceIndex": 0,
                                "groupSet": {"items": [{"groupId": "sg-0aebfa21f302bded9"}]},
                            },
                        ],
                    },
                    "privateDnsNameOptions": {
                        "enableResourceNameDnsAAAARecord": False,
                        "enableResourceNameDnsARecord": True,
                        "hostnameType": "ip-name",
                    },
                    "tagSpecificationSet": {
                        "items": [{"resourceType": "instance", "tags": [{"key": "Name", "value": "test2"}]}],
                    },
                },
                "responseElements": {
                    "groupSet": {},
                    "instancesSet": {
                        "items": [
                            {
                                "amiLaunchIndex": 0,
                                "architecture": "x86_64",
                                "blockDeviceMapping": {},
                                "capacityReservationSpecification": {"capacityReservationPreference": "open"},
                                "cpuOptions": {"coreCount": 1, "threadsPerCore": 1},
                                "currentInstanceBootMode": "bios",
                                "ebsOptimized": False,
                                "enaSupport": True,
                                "enclaveOptions": {"enabled": False},
                                "groupSet": {
                                    "items": [{"groupId": "sg-0aebfa21f302bded9", "groupName": "launch-wizard-4"}],
                                },
                                "hypervisor": "xen",
                                "imageId": "ami-026b57f3c383c2eec",
                                "instanceId": "i-0d7e4b9be8a0de6ea",
                                "instanceState": {"code": 0, "name": "pending"},
                                "instanceType": "t1.micro",
                                "keyName": "kp1",
                                "launchTime": 1666275403000.0,
                                "maintenanceOptions": {"autoRecovery": "default"},
                                "metadataOptions": {
                                    "httpEndpoint": "enabled",
                                    "httpProtocolIpv4": "enabled",
                                    "httpProtocolIpv6": "disabled",
                                    "httpPutResponseHopLimit": 1,
                                    "httpTokens": "optional",
                                    "instanceMetadataTags": "disabled",
                                    "state": "pending",
                                },
                                "monitoring": {"state": "disabled"},
                                "networkInterfaceSet": {
                                    "items": [
                                        {
                                            "attachment": {
                                                "attachTime": 1666275403000.0,
                                                "attachmentId": "eni-attach-0f01abecb268392c1",
                                                "deleteOnTermination": True,
                                                "deviceIndex": 0,
                                                "networkCardIndex": 0,
                                                "status": "attaching",
                                            },
                                            "groupSet": {
                                                "items": [
                                                    {"groupId": "sg-0aebfa21f302bded9", "groupName": "launch-wizard-4"},
                                                ],
                                            },
                                            "interfaceType": "interface",
                                            "ipv6AddressesSet": {},
                                            "macAddress": "0a:47:b4:21:fe:8d",
                                            "networkInterfaceId": "eni-08b298299ee7c922c",
                                            "ownerId": "123123123123",
                                            "privateDnsName": "ip-111.111.111.111.ec2.internal",
                                            "privateIpAddress": "111.111.111.111",
                                            "privateIpAddressesSet": {
                                                "item": [
                                                    {
                                                        "primary": True,
                                                        "privateDnsName": "ip-111.111.111.111.ec2.internal",
                                                        "privateIpAddress": "111.111.111.111",
                                                    },
                                                ],
                                            },
                                            "sourceDestCheck": True,
                                            "status": "in-use",
                                            "subnetId": "subnet-0ae6d533cb0b18193",
                                            "tagSet": {},
                                            "vpcId": "vpc-0f59e8f1222b0de6a",
                                        },
                                    ],
                                },
                                "placement": {"availabilityZone": "us-east-1a", "tenancy": "default"},
                                "privateDnsName": "ip-111.111.111.111.ec2.internal",
                                "privateDnsNameOptions": {
                                    "enableResourceNameDnsAAAARecord": False,
                                    "enableResourceNameDnsARecord": True,
                                    "hostnameType": "ip-name",
                                },
                                "privateIpAddress": "111.111.111.111",
                                "productCodes": {},
                                "rootDeviceName": "/dev/xvda",
                                "rootDeviceType": "ebs",
                                "sourceDestCheck": True,
                                "stateReason": {"code": "pending", "message": "pending"},
                                "subnetId": "subnet-0ae6d533cb0b18193",
                                "tagSet": {"items": [{"key": "Name", "value": "test2"}]},
                                "virtualizationType": "hvm",
                                "vpcId": "vpc-0f59e8f1222b0de6a",
                            },
                        ],
                    },
                    "ownerId": "123123123123",
                    "requestId": "25c95576-a825-44fd-971d-5a52c1e3b2be",
                    "reservationId": "r-02debcf2c4878bc7f",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIA5PZQZ5QHAW6RFPO5",
                    "accountId": "123123123123",
                    "arn": "arn:aws:sts::123123123123:assumed-role/DevAdministrator/temp_user",
                    "principalId": "AROA5PZQZ5QHBULW27VAC:temp_user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-10-20T14:14:22Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123123123123",
                            "arn": "arn:aws:iam::123123123123:role/DevAdministrator",
                            "principalId": "AROA5PZQZ5QHBULW27VAC",
                            "type": "Role",
                            "userName": "DevAdministrator",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="RunInstance - Dry Run ",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "errorCode": "Client.DryRunOperation",
                "errorMessage": "Request would have succeeded, but DryRun flag is set.",
                "eventCategory": "Management",
                "eventID": "ab804e72-7237-49c6-8f20-c3ef09859e78",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-10-13 16:35:33",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123123123123"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123123123123:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup",
                    "arn:aws:sts::123123123123:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS",
                ],
                "p_any_domain_names": ["eks-nodegroup.amazonaws.com"],
                "p_any_usernames": ["AWSServiceRoleForAmazonEKSNodegroup"],
                "p_event_time": "2022-10-13 16:35:33",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-10-13 16:42:16.583",
                "p_row_id": "464736612772b0bd8dd8c5fc1384d209",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "Panther Identity Org CloudTrail",
                "readOnly": False,
                "recipientAccountId": "123123123123",
                "requestID": "5e7636b9-d5b5-4bb1-8e37-f98ae7c04e52",
                "requestParameters": {
                    "availabilityZone": "us-west-2b",
                    "blockDeviceMapping": {},
                    "clientToken": "27bec563-7673-4b80-8e00-3537e3b7ad6b",
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "instanceType": "m5.xlarge",
                    "instancesSet": {"items": [{"maxCount": 1, "minCount": 1}]},
                    "launchTemplate": {"launchTemplateId": "lt-0622a7ff26539376a", "version": "4"},
                    "monitoring": {"enabled": False},
                    "subnetId": "subnet-0d465e7cad854a993",
                },
                "sourceIPAddress": "eks-nodegroup.amazonaws.com",
                "userAgent": "eks-nodegroup.amazonaws.com",
                "userIdentity": {
                    "accountId": "123123123123",
                    "arn": "arn:aws:sts::123123123123:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS",
                    "invokedBy": "eks-nodegroup.amazonaws.com",
                    "principalId": "AROAZBD2CNPWD5DHZ366F:EKS",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-10-13T16:35:31Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123123123123",
                            "arn": "arn:aws:iam::123123123123:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup",
                            "principalId": "AROAZBD2CNPWD5DHZ366F",
                            "type": "Role",
                            "userName": "AWSServiceRoleForAmazonEKSNodegroup",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="CopyImage - UserIdentity Null",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "0ea3f05a-066c-43f9-8869-393ba67e7936",
                "eventName": "CreateImage",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-09-29 22:25:17",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "123456789101",
                "requestID": "e686939a-a08a-4fd6-abf5-ffffffffffff",
                "requestParameters": {
                    "blockDeviceMapping": {
                        "items": [{"deviceName": "/dev/xvda", "ebs": {"deleteOnTermination": True, "volumeSize": 8}}],
                    },
                    "instanceId": "i-0381a3817f72a949d",
                    "name": "testimage",
                    "noReboot": False,
                },
                "responseElements": {
                    "imageId": "ami-06aaf5e4b77161786",
                    "requestId": "e686939a-a08a-4fd6-abf5-9ea34793cf25",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIA5PZQZ5QHE2FUNXHR",
                    "accountId": "123456789101",
                    "arn": "arn:aws:sts::123456789101:assumed-role/DevAdministrator/test_user",
                    "principalId": "AROA5PZQZ5QHBULW27VAC:test_user",
                    "invokedBy": None,
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-29T22:22:46Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123456789101",
                            "arn": "arn:aws:iam::123456789101:role/DevAdministrator",
                            "principalId": "AROA5PZQZ5QHBULW27VAC",
                            "type": "Role",
                            "userName": "DevAdministrator",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
