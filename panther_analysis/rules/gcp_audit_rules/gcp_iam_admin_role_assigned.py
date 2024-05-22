from fnmatch import fnmatch
from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get, get_binding_deltas

gcpiam_admin_role_assigned_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Service Admin Role Assigned",
        ExpectedResult=True,
        Log={
            "logName": "projects/eastern-nurve-222999/logs/cloudaudit.googleapis.com%2Factivity",
            "severity": "NOTICE",
            "insertId": "-4fgf8odw6xy",
            "resource": {"type": "project", "labels": {"project_id": "eastern-nurve-222999"}},
            "timestamp": "2020-05-04 20:53:02.915000000",
            "receiveTimestamp": "2020-05-04 20:53:04.281679681",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "methodName": "SetIamPolicy",
                "resourceName": "projects/eastern-nurve-222999",
                "status": {},
                "authenticationInfo": {"principalEmail": "test@runpanther.io"},
                "authorizationInfo": [
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                ],
                "requestMetadata": {
                    "callerIP": "136.24.229.58",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,gzip(gfe)",
                    "requestAttributes": {},
                    "destinationAttributes": {},
                },
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {
                        "bindings": [
                            {
                                "members": [
                                    "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                                ],
                                "role": "roles/compute.serviceAgent",
                            },
                            {
                                "members": [
                                    "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                    "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                                ],
                                "role": "roles/editor",
                            },
                            {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.subscriber",
                            },
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.viewer",
                            },
                            {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        ],
                        "etag": "BwWk11rbCfY=",
                    },
                    "resource": "eastern-nurve-222999",
                },
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [
                        {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        {
                            "members": [
                                "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                            ],
                            "role": "roles/compute.serviceAgent",
                        },
                        {
                            "members": [
                                "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                            ],
                            "role": "roles/editor",
                        },
                        {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.subscriber",
                        },
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.viewer",
                        },
                    ],
                    "etag": "BwWk2LeSpmA=",
                },
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "ADD",
                                "member": "user:test@runpanther.io",
                                "role": "roles/actions.Admin",
                            },
                            {
                                "action": "ADD",
                                "member": "user:test@runpanther.io",
                                "role": "roles/appengine.appAdmin",
                            },
                            {
                                "action": "REMOVE",
                                "member": "user:test@runpanther.io",
                                "role": "roles/browser",
                            },
                        ]
                    },
                },
            },
        },
    ),
    PantherRuleTest(
        Name="Admin Role Assigned",
        ExpectedResult=True,
        Log={
            "logName": "projects/eastern-nurve-222999/logs/cloudaudit.googleapis.com%2Factivity",
            "severity": "NOTICE",
            "insertId": "-4fgf8odw6xy",
            "resource": {"type": "project", "labels": {"project_id": "eastern-nurve-222999"}},
            "timestamp": "2020-05-04 20:53:02.915000000",
            "receiveTimestamp": "2020-05-04 20:53:04.281679681",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "methodName": "SetIamPolicy",
                "resourceName": "projects/eastern-nurve-222999",
                "status": {},
                "authenticationInfo": {"principalEmail": "test@runpanther.io"},
                "authorizationInfo": [
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                ],
                "requestMetadata": {
                    "callerIP": "136.24.229.58",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,gzip(gfe)",
                    "requestAttributes": {},
                    "destinationAttributes": {},
                },
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {
                        "bindings": [
                            {
                                "members": [
                                    "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                                ],
                                "role": "roles/compute.serviceAgent",
                            },
                            {
                                "members": [
                                    "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                    "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                                ],
                                "role": "roles/editor",
                            },
                            {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.subscriber",
                            },
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.viewer",
                            },
                            {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        ],
                        "etag": "BwWk11rbCfY=",
                    },
                    "resource": "eastern-nurve-222999",
                },
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [
                        {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        {
                            "members": [
                                "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                            ],
                            "role": "roles/compute.serviceAgent",
                        },
                        {
                            "members": [
                                "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                            ],
                            "role": "roles/editor",
                        },
                        {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.subscriber",
                        },
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.viewer",
                        },
                    ],
                    "etag": "BwWk2LeSpmA=",
                },
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "ADD",
                                "member": "user:test@gmail.com",
                                "role": "roles/owner",
                            }
                        ]
                    },
                },
            },
        },
    ),
    PantherRuleTest(
        Name="Browser Role Assigned",
        ExpectedResult=False,
        Log={
            "logName": "projects/eastern-nurve-222999/logs/cloudaudit.googleapis.com%2Factivity",
            "severity": "NOTICE",
            "insertId": "-4fgf8odw6xy",
            "resource": {"type": "project", "labels": {"project_id": "eastern-nurve-222999"}},
            "timestamp": "2020-05-04 20:53:02.915000000",
            "receiveTimestamp": "2020-05-04 20:53:04.281679681",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "methodName": "SetIamPolicy",
                "resourceName": "projects/eastern-nurve-222999",
                "status": {},
                "authenticationInfo": {"principalEmail": "test@runpanther.io"},
                "authorizationInfo": [
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                    {
                        "resource": "projects/eastern-nurve-222999",
                        "permission": "resourcemanager.projects.setIamPolicy",
                        "granted": True,
                    },
                ],
                "requestMetadata": {
                    "callerIP": "136.24.229.58",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,gzip(gfe)",
                    "requestAttributes": {},
                    "destinationAttributes": {},
                },
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {
                        "bindings": [
                            {
                                "members": [
                                    "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                                ],
                                "role": "roles/compute.serviceAgent",
                            },
                            {
                                "members": [
                                    "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                    "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                                ],
                                "role": "roles/editor",
                            },
                            {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.subscriber",
                            },
                            {
                                "members": [
                                    "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                                ],
                                "role": "roles/pubsub.viewer",
                            },
                            {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        ],
                        "etag": "BwWk11rbCfY=",
                    },
                    "resource": "eastern-nurve-222999",
                },
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [
                        {"members": ["user:test@gmail.com"], "role": "roles/browser"},
                        {
                            "members": [
                                "serviceAccount:service-951849100836@compute-system.iam.gserviceaccount.com"
                            ],
                            "role": "roles/compute.serviceAgent",
                        },
                        {
                            "members": [
                                "serviceAccount:951849100836-compute@developer.gserviceaccount.com",
                                "serviceAccount:951849100836@cloudservices.gserviceaccount.com",
                            ],
                            "role": "roles/editor",
                        },
                        {"members": ["user:test@runpanther.io"], "role": "roles/owner"},
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.subscriber",
                        },
                        {
                            "members": [
                                "serviceAccount:pubsub-reader@eastern-nurve-222999.iam.gserviceaccount.com"
                            ],
                            "role": "roles/pubsub.viewer",
                        },
                    ],
                    "etag": "BwWk2LeSpmA=",
                },
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "ADD",
                                "member": "user:test@gmail.com",
                                "role": "roles/browser",
                            }
                        ]
                    },
                },
            },
        },
    ),
]


class GCPIAMAdminRoleAssigned(PantherRule):
    RuleID = "GCP.IAM.AdminRoleAssigned-prototype"
    DisplayName = "--DEPRECATED-- GCP IAM Admin Role Assigned"
    Enabled = False
    LogTypes = ["GCP.AuditLog"]
    Tags = [
        "GCP",
        "Identity & Access Management",
        "Privilege Escalation:Valid Accounts",
        "Configuration Required",
        "Deprecated",
    ]
    Reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    Severity = Severity.Medium
    Description = "Attaching an admin role manually could be a sign of privilege escalation"
    Runbook = "Verify with the user who attached the role or add to a allowlist"
    Reference = "https://cloud.google.com/looker/docs/admin-panel-users-roles"
    SummaryAttributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = gcpiam_admin_role_assigned_tests
    # Primitive Roles
    # Predefined Roles
    ADMIN_ROLES = {"roles/owner", "roles/*Admin"}

    def rule(self, event):
        for delta in get_binding_deltas(event):
            if delta.get("action") != "ADD":
                continue
            if any(
                (
                    fnmatch(delta.get("role", ""), admin_role_pattern)
                    for admin_role_pattern in self.ADMIN_ROLES
                )
            ):
                return True
        return False

    def title(self, event):
        return f"An admin role has been configured in GCP project {deep_get(event, 'resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"
