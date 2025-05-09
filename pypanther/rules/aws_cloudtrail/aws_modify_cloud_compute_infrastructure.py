from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSModifyCloudComputeInfrastructure(Rule):
    default_description = (
        "Detection when EC2 compute infrastructure is modified outside of expected automation methods."
    )
    display_name = "AWS Modify Cloud Compute Infrastructure"
    enabled = False
    default_reference = "https://attack.mitre.org/techniques/T1578/"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1578"]}
    tags = ["Configuration Required"]
    default_runbook = "This detection reports on eventSource ec2 Change events. This detection excludes Cross-Service change events.  As such, this detection will perform well in environments where changes are expected to originate only from AWS service entities.\nThis detection will emit alerts frequently in environments where users are making ec2 related changes.\n"
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.Modify.Cloud.Compute.Infrastructure-prototype"
    EC2_CRUD_ACTIONS = {
        "AssociateIamInstanceProfile",
        "AssociateInstanceEventWindow",
        "BundleInstance",
        "CancelSpotInstanceRequests",
        "ConfirmProductInstance",
        "CreateInstanceEventWindow",
        "CreateInstanceExportTask",
        "DeleteInstanceEventWindow",
        "DeregisterInstanceEventNotificationAttributes",
        "DisassociateIamInstanceProfile",
        "DisassociateInstanceEventWindow",
        "ImportInstance",
        "ModifyInstanceAttribute",
        "ModifyInstanceCapacityReservationAttributes",
        "ModifyInstanceCreditSpecification",
        "ModifyInstanceEventStartTime",
        "ModifyInstanceEventWindow",
        "ModifyInstanceMaintenanceOptions",
        "ModifyInstanceMetadataOptions",
        "ModifyInstancePlacement",
        "MonitorInstances",
        "RegisterInstanceEventNotificationAttributes",
        "ReportInstanceStatus",
        "RequestSpotInstances",
        "ResetInstanceAttribute",
        "RunInstances",
        "RunScheduledInstances",
        "StartInstances",
        "StopInstances",
        "TerminateInstances",
        "UnmonitorInstances",
    }

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
        # Disqualify any eventNames that do not Include instance
        # and events that have readOnly set to false
        if event.get("eventName", "") in self.EC2_CRUD_ACTIONS:
            return True
        return False

    def title(self, event):
        items = event.deep_get("requestParameters", "instancesSet", "items", default=[{"instanceId": "none"}])
        return f"AWS Event [{event.get('eventName')}] Instance ID [{items[0].get('instanceId')}] AWS Account ID [{event.get('recipientAccountId')}]"

    def alert_context(self, event):
        items = event.deep_get("requestParameters", "instancesSet", "items", default=[{"instanceId": "none"}])
        return {
            "awsRegion": event.get("awsRegion"),
            "eventName": event.get("eventName"),
            "recipientAccountId": event.get("recipientAccountId"),
            "instanceId": items[0].get("instanceId"),
        }

    tests = [
        RuleTest(
            name="Terminate Instance from AssumedRole",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "59e8d6b8-de7b-43ca-961f-0c6f4531fcf0",
                "eventName": "TerminateInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2021-10-29 23:50:09",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["111222333444"],
                "p_any_aws_arns": ["arn:aws:iam::111222333444:role/FakeRole"],
                "p_any_aws_instance_ids": ["i-0d9853f67e40ab80b"],
                "p_any_domain_names": ["ec2.amazonaws.com"],
                "p_event_time": "2021-10-29 23:50:09",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2021-10-29 23:54:06.45",
                "p_row_id": "e6f7bd65083bfeb7feced38f0da18a01",
                "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
                "p_source_label": "SomeCloudTrail",
                "readOnly": False,
                "recipientAccountId": "111222333444",
                "requestID": "a520eeaf-c258-4260-954e-b4a976e6c72b",
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-0d9853f67e40ab80b"}]}},
                "responseElements": {
                    "instancesSet": {
                        "items": [
                            {
                                "currentState": {"code": 32, "name": "shutting-down"},
                                "instanceId": "i-0d9853f67e40ab80b",
                                "previousState": {"code": 16, "name": "running"},
                            },
                        ],
                    },
                    "requestId": "a520eeaf-c258-4260-954e-b4a976e6c72b",
                },
                "userIdentity": {
                    "accountId": "111222333444",
                    "arn": "arn:aws:sts::111222333444:assumed-role/SomeRole/AThing",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-29T23:50:08Z", "mfaAuthenticated": "false"},
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Terminate Instance from autoscaling",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventID": "59e8d6b8-de7b-43ca-961f-0c6f4531fcf0",
                "eventName": "TerminateInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2021-10-29 23:50:09",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["111222333444"],
                "p_any_aws_arns": [
                    "arn:aws:iam::111222333444:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                    "arn:aws:sts::111222333444:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling",
                ],
                "p_any_aws_instance_ids": ["i-0d9853f67e40ab80b"],
                "p_any_domain_names": ["autoscaling.amazonaws.com"],
                "p_event_time": "2021-10-29 23:50:09",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2021-10-29 23:54:06.45",
                "p_row_id": "e6f7bd65083bfeb7feced38f0da18a01",
                "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
                "p_source_label": "SomeCloudTrail",
                "readOnly": False,
                "recipientAccountId": "111222333444",
                "requestID": "a520eeaf-c258-4260-954e-b4a976e6c72b",
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-0d9853f67e40ab80b"}]}},
                "responseElements": {
                    "instancesSet": {
                        "items": [
                            {
                                "currentState": {"code": 32, "name": "shutting-down"},
                                "instanceId": "i-0d9853f67e40ab80b",
                                "previousState": {"code": 16, "name": "running"},
                            },
                        ],
                    },
                    "requestId": "a520eeaf-c258-4260-954e-b4a976e6c72b",
                },
                "sourceIPAddress": "autoscaling.amazonaws.com",
                "userAgent": "autoscaling.amazonaws.com",
                "userIdentity": {
                    "accountId": "111222333444",
                    "arn": "arn:aws:sts::111222333444:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling",
                    "invokedBy": "autoscaling.amazonaws.com",
                    "principalId": "AROATSZWD7TDLUEWEUXXI:AutoScaling",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-29T23:50:08Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111222333444",
                            "arn": "arn:aws:iam::111222333444:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                            "principalId": "AROATSZWD7TDLUEWEUXXI",
                            "type": "Role",
                            "userName": "AWSServiceRoleForAutoScaling",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Get Partition",
            expected_result=False,
            log={
                "additionalEventData": {
                    "insufficientLakeFormationPermissions": ["panther_rule_errors:gsuite_activityevent"],
                    "lakeFormationPrincipal": "arn:aws:iam::111222333444:role/panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S",
                },
                "awsRegion": "us-east-1",
                "errorCode": "EntityNotFoundException",
                "errorMessage": "Cannot find partition.",
                "eventID": "8780fc6b-7742-4a45-b757-c351a54c79b8",
                "eventName": "GetPartition",
                "eventSource": "glue.amazonaws.com",
                "eventTime": "2021-10-14 14:21:22",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["111222333444"],
                "p_any_aws_arns": [
                    "arn:aws:iam::111222333444:role/panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S",
                    "arn:aws:sts::111222333444:assumed-role/panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S/panther-datacatalog-compactor",
                ],
                "p_any_ip_addresses": ["54.90.94.136"],
                "p_event_time": "2021-10-14 14:21:22",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2021-10-14 14:27:06.54",
                "p_row_id": "7235e51c49e780a5a4e281e90c850c",
                "p_source_id": "5f9f0f60-9c56-4027-b93a-8bab3019f0f1",
                "p_source_label": "SomeCloudTrail",
                "readOnly": True,
                "recipientAccountId": "111222333444",
                "requestID": "cdb450f7-1cd8-463b-8449-71274d95a5a3",
                "requestParameters": {
                    "databaseName": "panther_rule_errors",
                    "partitionValues": ["2021", "10", "13", "19", "1634151600"],
                    "tableName": "gsuite_activityevent",
                },
                "sourceIPAddress": "54.90.94.136",
                "userAgent": "aws-sdk-go/1.40.21 (go1.17; linux; amd64) exec-env/AWS_Lambda_go1.x",
                "userIdentity": {
                    "accessKeyId": "ASIAJMVY5WC5K4TDFNFA",
                    "accountId": "111222333444",
                    "arn": "arn:aws:sts::111222333444:assumed-role/panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S/panther-datacatalog-compactor",
                    "principalId": "AROA4UN2W2PXWZMJ2L3PC:panther-datacatalog-compactor",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-14T14:20:28Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111222333444",
                            "arn": "arn:aws:iam::111222333444:role/panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S",
                            "principalId": "AROA4UN2W2PXWZMJ2L3PC",
                            "type": "Role",
                            "userName": "panther-Panther-4JL51Q6AU6SH-LogAnal-CompactorRole-W1WCIV3PHU0S",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Terminate instance From WebUI with assumedRole",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "01f39d3b-4a26-4045-bb36-1e57b7d07997",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-10-14 00:35:36",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123412341234:role/SomeRole",
                    "arn:aws:sts::123412341234:assumed-role/SomeRole/person",
                ],
                "p_any_aws_instance_ids": ["i-0690cd354a0c3850c"],
                "p_any_aws_tags": ["Name:fake thing whatever"],
                "p_any_domain_names": ["AWS Internal", "ip-10-1-0-14.us-west-2.compute.internal"],
                "p_any_ip_addresses": ["10.1.0.14"],
                "p_any_trace_ids": ["ASIARLIVEKVNGOY5UABO"],
                "p_any_usernames": ["SomeRole"],
                "p_event_time": "2022-10-14 00:35:36",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-10-14 00:38:26.875",
                "p_row_id": "76663c86299fc3f2fa94acfd13f29311",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "SomeCloudTrail",
                "readOnly": False,
                "recipientAccountId": "123412341234",
                "requestID": "557e2d68-904a-4fe7-81d4-33c056444a13",
                "requestParameters": {
                    "blockDeviceMapping": {},
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "ebsOptimized": False,
                    "instanceType": "t2.micro",
                    "instancesSet": {"items": [{"imageId": "ami-08e2d37b6a0129927", "maxCount": 1, "minCount": 1}]},
                    "monitoring": {"enabled": False},
                    "networkInterfaceSet": {
                        "items": [
                            {
                                "associatePublicIpAddress": False,
                                "deviceIndex": 0,
                                "groupSet": {"items": [{"groupId": "sg-0077c778d7ad1f5f2"}]},
                                "subnetId": "subnet-0e3a508e43776c435",
                            },
                        ],
                    },
                    "privateDnsNameOptions": {
                        "enableResourceNameDnsAAAARecord": False,
                        "enableResourceNameDnsARecord": True,
                        "hostnameType": "ip-name",
                    },
                    "tagSpecificationSet": {
                        "items": [
                            {"resourceType": "instance", "tags": [{"key": "Name", "value": "fake thing whatever"}]},
                        ],
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
                                "ebsOptimized": False,
                                "enaSupport": True,
                                "enclaveOptions": {"enabled": False},
                                "groupSet": {
                                    "items": [{"groupId": "sg-0077c778d7ad1f5f2", "groupName": "launch-wizard-1"}],
                                },
                                "hypervisor": "xen",
                                "imageId": "ami-08e2d37b6a0129927",
                                "instanceId": "i-0690cd354a0c3850c",
                                "instanceState": {"code": 0, "name": "pending"},
                                "instanceType": "t2.micro",
                                "launchTime": 1665707736000,
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
                                                "attachTime": 1665707736000,
                                                "attachmentId": "eni-attach-0b2f21743e26b7c8a",
                                                "deleteOnTermination": True,
                                                "deviceIndex": 0,
                                                "networkCardIndex": 0,
                                                "status": "attaching",
                                            },
                                            "groupSet": {
                                                "items": [
                                                    {"groupId": "sg-0077c778d7ad1f5f2", "groupName": "launch-wizard-1"},
                                                ],
                                            },
                                            "interfaceType": "interface",
                                            "ipv6AddressesSet": {},
                                            "macAddress": "02:50:9d:da:61:79",
                                            "networkInterfaceId": "eni-0f4e4d2d71627dd38",
                                            "ownerId": "123412341234",
                                            "privateDnsName": "ip-10-1-0-14.us-west-2.compute.internal",
                                            "privateIpAddress": "10.1.0.14",
                                            "privateIpAddressesSet": {
                                                "item": [
                                                    {
                                                        "primary": True,
                                                        "privateDnsName": "ip-10-1-0-14.us-west-2.compute.internal",
                                                        "privateIpAddress": "10.1.0.14",
                                                    },
                                                ],
                                            },
                                            "sourceDestCheck": True,
                                            "status": "in-use",
                                            "subnetId": "subnet-0e3a508e43776c435",
                                            "tagSet": {},
                                            "vpcId": "vpc-04fe895571b367c47",
                                        },
                                    ],
                                },
                                "placement": {"availabilityZone": "us-west-2a", "tenancy": "default"},
                                "privateDnsName": "ip-10-1-0-14.us-west-2.compute.internal",
                                "privateDnsNameOptions": {
                                    "enableResourceNameDnsAAAARecord": False,
                                    "enableResourceNameDnsARecord": True,
                                    "hostnameType": "ip-name",
                                },
                                "privateIpAddress": "10.1.0.14",
                                "productCodes": {},
                                "rootDeviceName": "/dev/xvda",
                                "rootDeviceType": "ebs",
                                "sourceDestCheck": True,
                                "stateReason": {"code": "pending", "message": "pending"},
                                "subnetId": "subnet-0e3a508e43776c435",
                                "tagSet": {"items": [{"key": "Name", "value": "fake thing whatever"}]},
                                "virtualizationType": "hvm",
                                "vpcId": "vpc-04fe895571b367c47",
                            },
                        ],
                    },
                    "ownerId": "123412341234",
                    "requestId": "557e2d68-904a-4fe7-81d4-33c056444a13",
                    "reservationId": "r-0de81af4b677c0252",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIARLIVEKVNGOY5UABO",
                    "accountId": "123412341234",
                    "arn": "arn:aws:sts::123412341234:assumed-role/SomeRole/person",
                    "principalId": "AROARLIVEKVNIRVGDLJWJ:person",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-10-14T00:34:59Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "123412341234",
                            "arn": "arn:aws:iam::123412341234:role/SomeRole",
                            "principalId": "AROARLIVEKVNIRVGDLJWJ",
                            "type": "Role",
                            "userName": "SomeRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Weird AWS Internal Message",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "errorCode": "Client.DryRunOperation",
                "errorMessage": "Request would have succeeded, but DryRun flag is set.",
                "eventCategory": "Management",
                "eventID": "b32f82e6-7375-4487-85f3-442face5eab4",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2022-10-13 16:34:53",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123412341234:role/funky-role-doing-dryrun",
                    "arn:aws:sts::123412341234:assumed-role/funky-role-doing-dryrun/1665678811",
                ],
                "p_any_domain_names": ["AWS Internal"],
                "p_any_usernames": ["funky-role-doing-dryrun"],
                "p_event_time": "2022-10-13 16:34:53",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-10-13 16:35:54.489",
                "p_row_id": "6650c5fe395984e0fdb7c1fc138ef507",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "SomeCloudTrail",
                "readOnly": False,
                "recipientAccountId": "123412341234",
                "requestID": "99288e91-d3a5-494b-9fe6-9fdc02646a16",
                "requestParameters": {
                    "blockDeviceMapping": {},
                    "clientToken": "80a552a2-30ee-419e-bd73-3ee36b1242d6",
                    "disableApiStop": False,
                    "disableApiTermination": False,
                    "instanceType": "m5.xlarge",
                    "instancesSet": {"items": [{"imageId": "ami-05074c40f29040248", "maxCount": 1, "minCount": 1}]},
                    "launchTemplate": {"launchTemplateId": "lt-064c1a4dbc97b01fc", "version": "5"},
                    "monitoring": {"enabled": False},
                    "subnetId": "subnet-00559b970d3a60983",
                },
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accountId": "123412341234",
                    "arn": "arn:aws:sts::123412341234:assumed-role/funky-role-doing-dryrun/astronomer-managed-1665678811",
                    "invokedBy": "AWS Internal",
                    "principalId": "AROAZBD2CNPWEWKWTLX67:astronomer-managed-1665678811",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-10-13T16:33:31Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123412341234",
                            "arn": "arn:aws:iam::123412341234:role/funky-role-doing-dryrun",
                            "principalId": "AROAZBD2CNPWEWKWTLX67",
                            "type": "Role",
                            "userName": "funky-role-doing-dryrun",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
