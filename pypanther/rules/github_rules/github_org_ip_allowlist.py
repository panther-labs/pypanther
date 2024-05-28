from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_org_ip_allowlist_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - IP Allow list modified",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "ip_allow_list_entry.create",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "org": "my-org",
        },
    ),
    PantherRuleTest(
        Name="GitHub - IP Allow list disabled",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "ip_allow_list.disable",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Non IP Allow list action",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "org.invite_user",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
        },
    ),
]


class GitHubOrgIpAllowlist(PantherRule):
    RuleID = "GitHub.Org.IpAllowlist-prototype"
    DisplayName = "GitHub Org IP Allow List modified"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Persistence:Account Manipulation"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Severity = PantherSeverity.Medium
    SummaryAttributes = ["actor", "action"]
    Description = "Detects changes to a GitHub Org IP Allow List"
    Runbook = "Verify that the change was authorized and appropriate."
    Reference = "https://docs.github.com/en/apps/maintaining-github-apps/managing-allowed-ip-addresses-for-a-github-app"
    Tests = git_hub_org_ip_allowlist_tests
    ALLOWLIST_ACTIONS = [
        "ip_allow_list.enable",
        "ip_allow_list.disable",
        "ip_allow_list.enable_for_installed_apps",
        "ip_allow_list.disable_for_installed_apps",
        "ip_allow_list_entry.create",
        "ip_allow_list_entry.update",
        "ip_allow_list_entry.destroy",
    ]

    def rule(self, event):
        return (
            event.get("action").startswith("ip_allow_list")
            and event.get("action") in self.ALLOWLIST_ACTIONS
        )

    def title(self, event):
        return f"GitHub Org IP Allow list modified by {event.get('actor')}."
