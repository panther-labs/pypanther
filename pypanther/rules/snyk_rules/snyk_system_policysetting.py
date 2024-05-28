from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_snyk_helpers import snyk_alert_context
from pypanther.log_types import LogType

snyk_system_policy_setting_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Snyk System Policy Setting event happened ( Security Policy )",
        ExpectedResult=True,
        Log={
            "content": {
                "after": {
                    "configuration": {
                        "rules": [
                            {
                                "actions": [
                                    {"data": {"severity": "high"}, "type": "severity-override"}
                                ],
                                "conditions": {
                                    "AND": [
                                        {
                                            "field": "exploit-maturity",
                                            "operator": "includes",
                                            "value": ["mature"],
                                        }
                                    ]
                                },
                                "name": "Rule 1",
                            }
                        ]
                    },
                    "description": "This is a security policy",
                    "group": "8fffffff-1555-4444-b000-b55555555555",
                    "name": "Example Security Policy",
                },
                "before": {},
                "publicId": "21111111-a222-4eee-8ddd-a99999999999",
            },
            "created": "2023-03-03 00:13:45.497",
            "event": "group.policy.create",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk System Policy Setting event happened ( License Policy )",
        ExpectedResult=True,
        Log={
            "content": {
                "after": {
                    "configuration": {
                        "licenses": [
                            {"instructions": "", "licenseType": "ADSL", "severity": "medium"},
                            {"instructions": "", "licenseType": "AGPL-3.0", "severity": "medium"},
                            {
                                "instructions": "",
                                "licenseType": "AGPL-3.0-only",
                                "severity": "high",
                            },
                        ]
                    },
                    "description": "this is a policy description",
                    "group": "8fffffff-1555-4444-b000-b55555555555",
                    "name": "Example License Policy",
                    "projectAttributes": {"criticality": [], "environment": [], "lifecycle": []},
                },
                "before": {},
                "publicId": "21111111-a222-4eee-8ddd-a99999999999",
            },
            "created": "2023-03-03 00:10:02.351",
            "event": "group.policy.create",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        },
    ),
    PantherRuleTest(
        Name="Snyk Group SSO Membership sync",
        ExpectedResult=False,
        Log={
            "content": {
                "addAsOrgAdmin": [],
                "addAsOrgCollaborator": ["group.name"],
                "addAsOrgCustomRole": [],
                "addAsOrgRestrictedCollaborator": [],
                "removedOrgMemberships": [],
                "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
            },
            "created": "2023-03-15 13:13:13.133",
            "event": "group.sso.membership.sync",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
        },
    ),
]


class SnykSystemPolicySetting(PantherRule):
    RuleID = "Snyk.System.PolicySetting-prototype"
    DisplayName = "Snyk System Policy Settings Changed"
    LogTypes = [LogType.Snyk_GroupAudit, LogType.Snyk_OrgAudit]
    Tags = ["Snyk"]
    Severity = PantherSeverity.High
    Description = "Detects Snyk Policy Settings have been changed. Policies define Snyk's behavior when encountering security and licensing issues.\n"
    Runbook = "Snyk Policies can cause alerts to raise or not based on found security and license issues. Validate that that this change is expected.\n"
    Reference = "https://docs.snyk.io/manage-issues/policies/shared-policies-overview"
    SummaryAttributes = ["event"]
    Tests = snyk_system_policy_setting_tests
    ACTIONS = [
        "group.policy.create",
        "group.policy.delete",
        "group.policy.edit",
        "org.policy.edit",
        "org.ignore_policy.edit",
    ]

    def rule(self, event):
        action = deep_get(event, "event", default="<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        policy_type = "<NO_POLICY_TYPE_FOUND>"
        license_or_rule = deep_get(event, "content", "after", "configuration", default={})
        if "rules" in license_or_rule:
            policy_type = "security"
        elif "licenses" in license_or_rule:
            policy_type = "license"
        return f"Snyk: System [{policy_type}] Policy Setting event [{deep_get(event, 'event', default='<NO_EVENT>')}] performed by [{deep_get(event, 'userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        a_c["policy_type"] = "<NO_POLICY_TYPE_FOUND>"
        license_or_rule = deep_get(event, "content", "after", "configuration", default={})
        if "rules" in license_or_rule:
            a_c["policy_type"] = "security"
        elif "licenses" in license_or_rule:
            a_c["policy_type"] = "license"
        return a_c

    def dedup(self, event):
        # Licenses can apply at org or group levels
        return f"{deep_get(event, 'userId', default='<NO_USERID>')}{deep_get(event, 'orgId', default='<NO_ORGID>')}{deep_get(event, 'groupId', default='<NO_GROUPID>')}{deep_get(event, 'content', 'publicId', default='<NO_PUBLICID>')}"
