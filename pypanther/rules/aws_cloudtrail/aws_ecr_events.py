from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSECREVENTS(Rule):
    id = "AWS.ECR.EVENTS-prototype"
    display_name = "AWS ECR Events"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control", "Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0005:T1535"]}
    default_severity = Severity.INFO
    create_alert = False
    default_description = "An ECR event occurred outside of an expected account or region"
    default_runbook = "https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html"
    default_reference = (
        "https://aws.amazon.com/blogs/containers/amazon-ecr-in-multi-account-and-multi-region-architectures/"
    )
    summary_attributes = ["eventSource", "recipientAccountId", "awsRegion", "p_any_aws_arns"]
    # CONFIGURATION REQUIRED: Update with your expected AWS Accounts/Regions
    AWS_ACCOUNTS_AND_REGIONS = {"123456789012": {"us-west-1", "us-west-2"}, "103456789012": {"us-east-1", "us-east-2"}}

    def rule(self, event):
        if event.get("eventSource") == "ecr.amazonaws.com":
            aws_account_id = event.deep_get("userIdentity", "accountId")
            if aws_account_id in self.AWS_ACCOUNTS_AND_REGIONS:
                if event.get("awsRegion") not in self.AWS_ACCOUNTS_AND_REGIONS[aws_account_id]:
                    return True
            else:
                return True
        return False

    def dedup(self, event):
        return event.get("recipientAccountId")

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Authorized account, unauthorized region",
            expected_result=True,
            log={
                "eventVersion": "1.04",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE:account_name",
                    "arn": "arn:aws:sts::123456789012:user/Mary_Major",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "Mary_Major",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-04-15T16:42:14Z"},
                    },
                },
                "eventTime": "2019-04-15T16:45:00Z",
                "eventSource": "ecr.amazonaws.com",
                "eventName": "PutImage",
                "awsRegion": "us-east-2",
                "sourceIPAddress": "203.0.113.12",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "repositoryName": "testrepo",
                    "imageTag": "latest",
                    "registryId": "123456789012",
                    "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                },
                "responseElements": {
                    "image": {
                        "repositoryName": "testrepo",
                        "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                        "registryId": "123456789012",
                        "imageId": {
                            "imageDigest": "sha256:98c8b060c21d9adbb6b8c41b916e95e6307102786973ab93a41e8b86d1fc6d3e",
                            "imageTag": "latest",
                        },
                    },
                },
                "requestID": "cf044b7d-5f9d-11e9-9b2a-95983139cc57",
                "eventID": "2bfd4ee2-2178-4a82-a27d-b12939923f0f",
                "resources": [
                    {"ARN": "arn:aws:ecr:us-east-2:123456789012:repository/testrepo", "accountId": "123456789012"},
                ],
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
        RuleTest(
            name="Unauthorized account",
            expected_result=True,
            log={
                "eventVersion": "1.04",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE:account_name",
                    "arn": "arn:aws:sts::123456789000:user/Mary_Major",
                    "accountId": "123456789000",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "Mary_Major",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-04-15T16:42:14Z"},
                    },
                },
                "eventTime": "2019-04-15T16:45:00Z",
                "eventSource": "ecr.amazonaws.com",
                "eventName": "PutImage",
                "awsRegion": "us-east-2",
                "sourceIPAddress": "203.0.113.12",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "repositoryName": "testrepo",
                    "imageTag": "latest",
                    "registryId": "123456789000",
                    "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                },
                "responseElements": {
                    "image": {
                        "repositoryName": "testrepo",
                        "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                        "registryId": "123456789000",
                        "imageId": {
                            "imageDigest": "sha256:98c8b060c21d9adbb6b8c41b916e95e6307102786973ab93a41e8b86d1fc6d3e",
                            "imageTag": "latest",
                        },
                    },
                },
                "requestID": "cf044b7d-5f9d-11e9-9b2a-95983139cc57",
                "eventID": "2bfd4ee2-2178-4a82-a27d-b12939923f0f",
                "resources": [
                    {"ARN": "arn:aws:ecr:us-east-2:123456789000:repository/testrepo", "accountId": "123456789000"},
                ],
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789000",
            },
        ),
        RuleTest(
            name="Authorized account",
            expected_result=False,
            log={
                "eventVersion": "1.04",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE:account_name",
                    "arn": "arn:aws:sts::123456789012:user/Mary_Major",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "Mary_Major",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2019-04-15T16:42:14Z"},
                    },
                },
                "eventTime": "2019-04-15T16:45:00Z",
                "eventSource": "ecr.amazonaws.com",
                "eventName": "PutImage",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "203.0.113.12",
                "userAgent": "console.amazonaws.com",
                "requestParameters": {
                    "repositoryName": "testrepo",
                    "imageTag": "latest",
                    "registryId": "123456789012",
                    "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                },
                "responseElements": {
                    "image": {
                        "repositoryName": "testrepo",
                        "imageManifest": '{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 5543,\n      "digest": "sha256:000b9b805af1cdb60628898c9f411996301a1c13afd3dbef1d8a16ac6dbf503a"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 43252507,\n         "digest": "sha256:3b37166ec61459e76e33282dda08f2a9cd698ca7e3d6bc44e6a6e7580cdeff8e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 846,\n         "digest": "sha256:504facff238fde83f1ca8f9f54520b4219c5b8f80be9616ddc52d31448a044bd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 615,\n         "digest": "sha256:ebbcacd28e101968415b0c812b2d2dc60f969e36b0b08c073bf796e12b1bb449"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 850,\n         "digest": "sha256:c7fb3351ecad291a88b92b600037e2435c84a347683d540042086fe72c902b8a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 168,\n         "digest": "sha256:2e3debadcbf7e542e2aefbce1b64a358b1931fb403b3e4aeca27cb4d809d56c2"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 37720774,\n         "digest": "sha256:f8c9f51ad524d8ae9bf4db69cd3e720ba92373ec265f5c390ffb21bb0c277941"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 30432107,\n         "digest": "sha256:813a50b13f61cf1f8d25f19fa96ad3aa5b552896c83e86ce413b48b091d7f01b"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 197,\n         "digest": "sha256:7ab043301a6187ea3293d80b30ba06c7bf1a0c3cd4c43d10353b31bc0cecfe7d"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 154,\n         "digest": "sha256:67012cca8f31dc3b8ee2305e7762fee20c250513effdedb38a1c37784a5a2e71"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 176,\n         "digest": "sha256:3bc892145603fffc9b1c97c94e2985b4cb19ca508750b15845a5d97becbd1a0e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 183,\n         "digest": "sha256:6f1c79518f18251d35977e7e46bfa6c6b9cf50df2a79d4194941d95c54258d18"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:b7bcfbc2e2888afebede4dd1cd5eebf029bb6315feeaf0b56e425e11a50afe42"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 212,\n         "digest": "sha256:2b220f8b0f32b7c2ed8eaafe1c802633bbd94849b9ab73926f0ba46cdae91629"\n      }\n   ]\n}',
                        "registryId": "123456789012",
                        "imageId": {
                            "imageDigest": "sha256:98c8b060c21d9adbb6b8c41b916e95e6307102786973ab93a41e8b86d1fc6d3e",
                            "imageTag": "latest",
                        },
                    },
                },
                "requestID": "cf044b7d-5f9d-11e9-9b2a-95983139cc57",
                "eventID": "2bfd4ee2-2178-4a82-a27d-b12939923f0f",
                "resources": [
                    {"ARN": "arn:aws:ecr:us-east-2:123456789012:repository/testrepo", "accountId": "123456789012"},
                ],
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
