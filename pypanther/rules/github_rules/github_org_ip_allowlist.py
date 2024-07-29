from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_hub_org_ip_allowlist_tests: list[RuleTest] = [
    RuleTest(
        name="GitHub - IP Allow list modified",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "ip_allow_list_entry.create",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "org": "my-org",
        },
    ),
    RuleTest(
        name="GitHub - IP Allow list disabled",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "ip_allow_list.disable",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
        },
    ),
    RuleTest(
        name="GitHub - Non IP Allow list action",
        expected_result=False,
        log={
            "actor": "cat",
            "action": "org.invite_user",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
        },
    ),
]


@panther_managed
class GitHubOrgIpAllowlist(Rule):
    id = "GitHub.Org.IpAllowlist-prototype"
    display_name = "GitHub Org IP Allow List modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_severity = Severity.MEDIUM
    summary_attributes = ["actor", "action"]
    default_description = "Detects changes to a GitHub Org IP Allow List"
    default_runbook = "Verify that the change was authorized and appropriate."
    default_reference = (
        "https://docs.github.com/en/apps/maintaining-github-apps/managing-allowed-ip-addresses-for-a-github-app"
    )
    tests = git_hub_org_ip_allowlist_tests
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
        return event.get("action").startswith("ip_allow_list") and event.get("action") in self.ALLOWLIST_ACTIONS

    def title(self, event):
        return f"GitHub Org IP Allow list modified by {event.get('actor')}."
