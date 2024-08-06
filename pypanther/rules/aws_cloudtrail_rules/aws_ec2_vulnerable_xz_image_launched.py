from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context
from pypanther.helpers.panther_default import aws_cloudtrail_success
from pypanther.helpers.panther_iocs import XZ_AMIS

awsec2_vulnerable_xz_image_launched_tests: list[RuleTest] = [
    RuleTest(
        name="Single vulnerable AMI Launched",
        expected_result=True,
        log={
            "awsRegion": "us-west-2",
            "eventCategory": "Management",
            "eventID": "cd7919fe-34a2-4d26-b038-23a2556a79fb",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2024-04-02 15:13:06.000000000",
            "eventType": "AwsApiCall",
            "eventVersion": "1.09",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "requestID": "439a7e66-d8b6-4bad-98d9-214c20161939",
            "requestParameters": {
                "blockDeviceMapping": {
                    "items": [
                        {
                            "deviceName": "/dev/sda1",
                            "ebs": {
                                "deleteOnTermination": True,
                                "encrypted": False,
                                "iops": 3000,
                                "snapshotId": "snap-00000000000000000",
                                "throughput": 125,
                                "volumeSize": 10,
                                "volumeType": "gp3",
                            },
                        },
                    ],
                },
                "clientToken": "00000000-0000-0000-0000-000000000000",
                "disableApiStop": False,
                "disableApiTermination": False,
                "ebsOptimized": True,
                "instanceType": "t3a.micro",
                "instancesSet": {
                    "items": [{"imageId": "ami-020a359780bc6f835", "keyName": "a-key", "maxCount": 1, "minCount": 1}],
                },
                "monitoring": {"enabled": False},
                "networkInterfaceSet": {
                    "items": [
                        {
                            "associatePublicIpAddress": True,
                            "deviceIndex": 0,
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000"}]},
                            "subnetId": "subnet-00000000000000000",
                        },
                    ],
                },
                "privateDnsNameOptions": {
                    "enableResourceNameDnsAAAARecord": False,
                    "enableResourceNameDnsARecord": False,
                    "hostnameType": "ip-name",
                },
                "tagSpecificationSet": {
                    "items": [{"resourceType": "instance", "tags": [{"key": "Name", "value": "test"}]}],
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
                            "clientToken": "8cda61da-eea9-495c-b178-e7014d9bc212",
                            "cpuOptions": {"coreCount": 1, "threadsPerCore": 2},
                            "currentInstanceBootMode": "legacy-bios",
                            "ebsOptimized": True,
                            "enaSupport": True,
                            "enclaveOptions": {"enabled": False},
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}]},
                            "hypervisor": "xen",
                            "imageId": "ami-020a359780bc6f835",
                            "instanceId": "i-00000000000000000",
                            "instanceState": {"code": 0, "name": "pending"},
                            "instanceType": "t3a.micro",
                            "keyName": "a-key",
                            "launchTime": 1712070786000,
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
                                            "attachTime": 1712070786000,
                                            "attachmentId": "eni-attach-00000000000000000",
                                            "deleteOnTermination": True,
                                            "deviceIndex": 0,
                                            "networkCardIndex": 0,
                                            "status": "attaching",
                                        },
                                        "groupSet": {
                                            "items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}],
                                        },
                                        "interfaceType": "interface",
                                        "ipv6AddressesSet": {},
                                        "macAddress": "06:71:c7:76:de:4f",
                                        "networkInterfaceId": "eni-00000000000000000",
                                        "ownerId": "123456789012",
                                        "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                                        "privateIpAddress": "10.0.0.3",
                                        "privateIpAddressesSet": {
                                            "item": [
                                                {
                                                    "primary": True,
                                                    "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                                                    "privateIpAddress": "10.0.0.3",
                                                },
                                            ],
                                        },
                                        "sourceDestCheck": True,
                                        "status": "in-use",
                                        "subnetId": "subnet-00000000000000000",
                                        "tagSet": {},
                                        "vpcId": "vpc-00000000000000000",
                                    },
                                ],
                            },
                            "placement": {"availabilityZone": "us-west-2b", "tenancy": "default"},
                            "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                            "privateDnsNameOptions": {
                                "enableResourceNameDnsAAAARecord": False,
                                "enableResourceNameDnsARecord": False,
                                "hostnameType": "ip-name",
                            },
                            "privateIpAddress": "10.0.0.3",
                            "productCodes": {},
                            "rootDeviceName": "/dev/sda1",
                            "rootDeviceType": "ebs",
                            "sourceDestCheck": True,
                            "stateReason": {"code": "pending", "message": "pending"},
                            "subnetId": "subnet-00000000000000000",
                            "tagSet": {"items": [{"key": "Name", "value": "test"}]},
                            "virtualizationType": "hvm",
                            "vpcId": "vpc-00000000000000000",
                        },
                    ],
                },
                "ownerId": "123456789012",
                "requestId": "439a7e66-d8b6-4bad-98d9-214c20161939",
                "reservationId": "r-00000000000000000",
            },
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "1.2.3.4",
            "tlsDetails": {
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                "tlsVersion": "TLSv1.3",
            },
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
            "userIdentity": {
                "accessKeyId": "ASIASXP6SDP2MXGX4MYC",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/user.name",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:user.name",
                "sessionContext": {
                    "attributes": {"creationDate": "2024-04-02T14:45:31Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "123456789012",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "ARole",
                    },
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="Multiple vulnerable AMIs Launched",
        expected_result=True,
        log={
            "awsRegion": "us-west-2",
            "eventCategory": "Management",
            "eventID": "762b9172-6148-4c76-aee4-f6fc0fd140af",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2024-04-02 16:46:24.000000000",
            "eventType": "AwsApiCall",
            "eventVersion": "1.09",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "requestID": "a71ca9b3-be94-4e22-95c5-e93b2280306c",
            "requestParameters": {
                "blockDeviceMapping": {
                    "items": [
                        {
                            "deviceName": "/dev/sda1",
                            "ebs": {
                                "deleteOnTermination": True,
                                "encrypted": False,
                                "iops": 3000,
                                "snapshotId": "snap-00000000000000000",
                                "throughput": 125,
                                "volumeSize": 6,
                                "volumeType": "gp3",
                            },
                        },
                    ],
                },
                "clientToken": "8945829d-0ef6-470d-bbfd-ea5bb2d82fdb",
                "disableApiStop": False,
                "disableApiTermination": False,
                "ebsOptimized": True,
                "instanceType": "t3a.nano",
                "instancesSet": {
                    "items": [{"imageId": "ami-092e3b17e435e5e58", "keyName": "a-key", "maxCount": 2, "minCount": 2}],
                },
                "monitoring": {"enabled": False},
                "networkInterfaceSet": {
                    "items": [
                        {
                            "associatePublicIpAddress": True,
                            "deviceIndex": 0,
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000"}]},
                            "subnetId": "subnet-00000000000000000",
                        },
                    ],
                },
                "privateDnsNameOptions": {
                    "enableResourceNameDnsAAAARecord": False,
                    "enableResourceNameDnsARecord": False,
                    "hostnameType": "ip-name",
                },
                "tagSpecificationSet": {
                    "items": [{"resourceType": "instance", "tags": [{"key": "Name", "value": "test"}]}],
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
                            "clientToken": "8945829d-0ef6-470d-bbfd-ea5bb2d82fdb",
                            "cpuOptions": {"coreCount": 1, "threadsPerCore": 2},
                            "currentInstanceBootMode": "legacy-bios",
                            "ebsOptimized": True,
                            "enaSupport": True,
                            "enclaveOptions": {"enabled": False},
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}]},
                            "hypervisor": "xen",
                            "imageId": "ami-092e3b17e435e5e58",
                            "instanceId": "i-00000000000000000",
                            "instanceState": {"code": 0, "name": "pending"},
                            "instanceType": "t3a.nano",
                            "keyName": "a-key",
                            "launchTime": 1712076384000,
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
                                            "attachTime": 1712076384000,
                                            "attachmentId": "eni-attach-00000000000000000",
                                            "deleteOnTermination": True,
                                            "deviceIndex": 0,
                                            "networkCardIndex": 0,
                                            "status": "attaching",
                                        },
                                        "groupSet": {
                                            "items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}],
                                        },
                                        "interfaceType": "interface",
                                        "ipv6AddressesSet": {},
                                        "macAddress": "06:18:9b:64:05:2b",
                                        "networkInterfaceId": "eni-00000000000000000",
                                        "ownerId": "123456789012",
                                        "privateDnsName": "ip-10-0-0-4.us-west-2.compute.internal",
                                        "privateIpAddress": "10.0.0.4",
                                        "privateIpAddressesSet": {
                                            "item": [
                                                {
                                                    "primary": True,
                                                    "privateDnsName": "ip-10-0-0-4.us-west-2.compute.internal",
                                                    "privateIpAddress": "10.0.0.4",
                                                },
                                            ],
                                        },
                                        "sourceDestCheck": True,
                                        "status": "in-use",
                                        "subnetId": "subnet-00000000000000000",
                                        "tagSet": {},
                                        "vpcId": "vpc-00000000000000000",
                                    },
                                ],
                            },
                            "placement": {"availabilityZone": "us-west-2b", "tenancy": "default"},
                            "privateDnsName": "ip-10-0-0-4.us-west-2.compute.internal",
                            "privateDnsNameOptions": {
                                "enableResourceNameDnsAAAARecord": False,
                                "enableResourceNameDnsARecord": False,
                                "hostnameType": "ip-name",
                            },
                            "privateIpAddress": "10.0.0.4",
                            "productCodes": {},
                            "rootDeviceName": "/dev/sda1",
                            "rootDeviceType": "ebs",
                            "sourceDestCheck": True,
                            "stateReason": {"code": "pending", "message": "pending"},
                            "subnetId": "subnet-00000000000000000",
                            "tagSet": {"items": [{"key": "Name", "value": "test"}]},
                            "virtualizationType": "hvm",
                            "vpcId": "vpc-00000000000000000",
                        },
                        {
                            "amiLaunchIndex": 1,
                            "architecture": "x86_64",
                            "blockDeviceMapping": {},
                            "capacityReservationSpecification": {"capacityReservationPreference": "open"},
                            "clientToken": "8945829d-0ef6-470d-bbfd-ea5bb2d82fdb",
                            "cpuOptions": {"coreCount": 1, "threadsPerCore": 2},
                            "currentInstanceBootMode": "legacy-bios",
                            "ebsOptimized": True,
                            "enaSupport": True,
                            "enclaveOptions": {"enabled": False},
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}]},
                            "hypervisor": "xen",
                            "imageId": "ami-020a359780bc6f835",
                            "instanceId": "i-00000000000000001",
                            "instanceState": {"code": 0, "name": "pending"},
                            "instanceType": "t3a.nano",
                            "keyName": "a-key",
                            "launchTime": 1712076384000,
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
                                            "attachTime": 1712076384000,
                                            "attachmentId": "eni-attach-00000000000000000",
                                            "deleteOnTermination": True,
                                            "deviceIndex": 0,
                                            "networkCardIndex": 0,
                                            "status": "attaching",
                                        },
                                        "groupSet": {
                                            "items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}],
                                        },
                                        "interfaceType": "interface",
                                        "ipv6AddressesSet": {},
                                        "macAddress": "06:b3:32:47:a8:c5",
                                        "networkInterfaceId": "eni-00000000000000000",
                                        "ownerId": "123456789012",
                                        "privateDnsName": "ip-10-0-0-5.us-west-2.compute.internal",
                                        "privateIpAddress": "10.0.0.5",
                                        "privateIpAddressesSet": {
                                            "item": [
                                                {
                                                    "primary": True,
                                                    "privateDnsName": "ip-10-0-0-5.us-west-2.compute.internal",
                                                    "privateIpAddress": "10.0.0.5",
                                                },
                                            ],
                                        },
                                        "sourceDestCheck": True,
                                        "status": "in-use",
                                        "subnetId": "subnet-00000000000000000",
                                        "tagSet": {},
                                        "vpcId": "vpc-00000000000000000",
                                    },
                                ],
                            },
                            "placement": {"availabilityZone": "us-west-2b", "tenancy": "default"},
                            "privateDnsName": "ip-10-0-0-5.us-west-2.compute.internal",
                            "privateDnsNameOptions": {
                                "enableResourceNameDnsAAAARecord": False,
                                "enableResourceNameDnsARecord": False,
                                "hostnameType": "ip-name",
                            },
                            "privateIpAddress": "10.0.0.5",
                            "productCodes": {},
                            "rootDeviceName": "/dev/sda1",
                            "rootDeviceType": "ebs",
                            "sourceDestCheck": True,
                            "stateReason": {"code": "pending", "message": "pending"},
                            "subnetId": "subnet-00000000000000000",
                            "tagSet": {"items": [{"key": "Name", "value": "test"}]},
                            "virtualizationType": "hvm",
                            "vpcId": "vpc-00000000000000000",
                        },
                    ],
                },
                "ownerId": "123456789012",
                "requestId": "a71ca9b3-be94-4e22-95c5-e93b2280306c",
                "reservationId": "r-00000000000000000",
            },
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "1.2.3.4",
            "tlsDetails": {
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                "tlsVersion": "TLSv1.3",
            },
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
            "userIdentity": {
                "accessKeyId": "ASIASXP6SDP2MBQCDGHR",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/user.name",
                "principalId": "00000000000000000:user.name",
                "sessionContext": {
                    "attributes": {"creationDate": "2024-04-02T16:09:04Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "123456789012",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "principalId": "00000000000000000",
                        "type": "Role",
                        "userName": "ARole",
                    },
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="Non-vulnerable AMI Launched",
        expected_result=False,
        log={
            "awsRegion": "us-west-2",
            "eventCategory": "Management",
            "eventID": "cd7919fe-34a2-4d26-b038-23a2556a79fb",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2024-04-02 15:13:06.000000000",
            "eventType": "AwsApiCall",
            "eventVersion": "1.09",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "requestID": "439a7e66-d8b6-4bad-98d9-214c20161939",
            "requestParameters": {
                "blockDeviceMapping": {
                    "items": [
                        {
                            "deviceName": "/dev/sda1",
                            "ebs": {
                                "deleteOnTermination": True,
                                "encrypted": False,
                                "iops": 3000,
                                "snapshotId": "snap-00000000000000000",
                                "throughput": 125,
                                "volumeSize": 10,
                                "volumeType": "gp3",
                            },
                        },
                    ],
                },
                "clientToken": "00000000-0000-0000-0000-000000000000",
                "disableApiStop": False,
                "disableApiTermination": False,
                "ebsOptimized": True,
                "instanceType": "t3a.micro",
                "instancesSet": {
                    "items": [{"imageId": "ami-08038de0f4f90a9f0", "keyName": "a-key", "maxCount": 1, "minCount": 1}],
                },
                "monitoring": {"enabled": False},
                "networkInterfaceSet": {
                    "items": [
                        {
                            "associatePublicIpAddress": True,
                            "deviceIndex": 0,
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000"}]},
                            "subnetId": "subnet-00000000000000000",
                        },
                    ],
                },
                "privateDnsNameOptions": {
                    "enableResourceNameDnsAAAARecord": False,
                    "enableResourceNameDnsARecord": False,
                    "hostnameType": "ip-name",
                },
                "tagSpecificationSet": {
                    "items": [{"resourceType": "instance", "tags": [{"key": "Name", "value": "test"}]}],
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
                            "clientToken": "8cda61da-eea9-495c-b178-e7014d9bc212",
                            "cpuOptions": {"coreCount": 1, "threadsPerCore": 2},
                            "currentInstanceBootMode": "legacy-bios",
                            "ebsOptimized": True,
                            "enaSupport": True,
                            "enclaveOptions": {"enabled": False},
                            "groupSet": {"items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}]},
                            "hypervisor": "xen",
                            "imageId": "ami-08038de0f4f90a9f0",
                            "instanceId": "i-00000000000000000",
                            "instanceState": {"code": 0, "name": "pending"},
                            "instanceType": "t3a.micro",
                            "keyName": "a-key",
                            "launchTime": 1712070786000,
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
                                            "attachTime": 1712070786000,
                                            "attachmentId": "eni-attach-00000000000000000",
                                            "deleteOnTermination": True,
                                            "deviceIndex": 0,
                                            "networkCardIndex": 0,
                                            "status": "attaching",
                                        },
                                        "groupSet": {
                                            "items": [{"groupId": "sg-00000000000000000", "groupName": "ssh"}],
                                        },
                                        "interfaceType": "interface",
                                        "ipv6AddressesSet": {},
                                        "macAddress": "06:71:c7:76:de:4f",
                                        "networkInterfaceId": "eni-00000000000000000",
                                        "ownerId": "123456789012",
                                        "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                                        "privateIpAddress": "10.0.0.3",
                                        "privateIpAddressesSet": {
                                            "item": [
                                                {
                                                    "primary": True,
                                                    "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                                                    "privateIpAddress": "10.0.0.3",
                                                },
                                            ],
                                        },
                                        "sourceDestCheck": True,
                                        "status": "in-use",
                                        "subnetId": "subnet-00000000000000000",
                                        "tagSet": {},
                                        "vpcId": "vpc-00000000000000000",
                                    },
                                ],
                            },
                            "placement": {"availabilityZone": "us-west-2b", "tenancy": "default"},
                            "privateDnsName": "ip-10-0-0-3.us-west-2.compute.internal",
                            "privateDnsNameOptions": {
                                "enableResourceNameDnsAAAARecord": False,
                                "enableResourceNameDnsARecord": False,
                                "hostnameType": "ip-name",
                            },
                            "privateIpAddress": "10.0.0.3",
                            "productCodes": {},
                            "rootDeviceName": "/dev/sda1",
                            "rootDeviceType": "ebs",
                            "sourceDestCheck": True,
                            "stateReason": {"code": "pending", "message": "pending"},
                            "subnetId": "subnet-00000000000000000",
                            "tagSet": {"items": [{"key": "Name", "value": "test"}]},
                            "virtualizationType": "hvm",
                            "vpcId": "vpc-00000000000000000",
                        },
                    ],
                },
                "ownerId": "123456789012",
                "requestId": "439a7e66-d8b6-4bad-98d9-214c20161939",
                "reservationId": "r-00000000000000000",
            },
            "sessionCredentialFromConsole": True,
            "sourceIPAddress": "1.2.3.4",
            "tlsDetails": {
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                "tlsVersion": "TLSv1.3",
            },
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
            "userIdentity": {
                "accessKeyId": "ASIASXP6SDP2MXGX4MYC",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/ARole/user.name",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:user.name",
                "sessionContext": {
                    "attributes": {"creationDate": "2024-04-02T14:45:31Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "123456789012",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/ARole",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "ARole",
                    },
                },
                "type": "AssumedRole",
            },
        },
    ),
]


@panther_managed
class AWSEC2VulnerableXZImageLaunched(Rule):
    default_description = (
        "Detecting EC2 instances launched with AMIs containing potentially vulnerable versions of XZ (CVE-2024-3094)\n"
    )
    display_name = "AWS EC2 Vulnerable XZ Image Launched"
    default_reference = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094"
    default_severity = Severity.CRITICAL
    tags = ["AWS", "Linux", "Emerging Threats", "Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.001"]}
    default_runbook = "- Verify that the AMI is indeed vulnerable to CVE-2024-3094 (xz -V being 5.6.0 or 5.6.1) - If the AMI is vulnerable, terminate the instance and launch a new instance with a non-vulnerable AMI\n"
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.EC2.Vulnerable.XZ.Image.Launched-prototype"
    tests = awsec2_vulnerable_xz_image_launched_tests
    # AMIs published by Fedora between 2024-03-26 and 2024-04-02
    # OpenSUSE and Kali do not have any recent [public] AMIs that would be affected

    def rule(self, event):
        if not aws_cloudtrail_success(event) or event.get("eventName") != "RunInstances":
            return False
        amis_launched = event.deep_walk(
            "responseElements",
            "instancesSet",
            "items",
            "imageId",
            default="<AMI ID not found>",
            return_val="all",
        )
        # convert to a list if only one item is returned
        if not isinstance(amis_launched, list):
            amis_launched = [amis_launched]
        if any(ami in XZ_AMIS for ami in amis_launched):
            return True
        return False

    def title(self, event):
        amis_launched = event.deep_walk(
            "responseElements",
            "instancesSet",
            "items",
            "imageId",
            default="<AMI ID not found>",
            return_val="all",
        )
        instance_ids = event.deep_walk(
            "responseElements",
            "instancesSet",
            "items",
            "instanceId",
            default="<Instance ID not found>",
            return_val="all",
        )
        return f"Instance {instance_ids} launched with vulnerable AMI: {amis_launched}"

    def alert_context(self, event):
        return aws_rule_context(event)
