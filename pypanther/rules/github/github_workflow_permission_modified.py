from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubWorkflowPermissionsModified(Rule):
    id = "GitHub.Workflow.PermissionsModified-prototype"
    display_name = "GitHub Workflow Permissions Modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects when the default workflow permissions for the GITHUB_TOKEN are modified at the organization level. GitHub Actions workflows use GITHUB_TOKEN for authentication, and changing these permissions can either expand or restrict what workflows can do by default. Unauthorized modifications could allow attackers to escalate privileges in CI/CD pipelines, potentially leading to supply chain compromise through malicious workflow modifications, unauthorized code deployments, or exfiltration of secrets. This is particularly concerning as it affects all repositories in the organization unless overridden at the repository level.\n"
    default_runbook = "1. Identify the actor who modified the workflow permissions by reviewing the alert details for the 'actor' and 'actor_id' fields.\n2. Verify the legitimacy of the change:\n   - Contact the user to confirm they made this change intentionally\n   - Check if there was a recent change request or ticket associated with this modification\n   - Verify the user's current role and whether they should have organization admin privileges\n3. Review the permission change details:\n   - Navigate to GitHub Organization Settings > Actions > General > Workflow permissions\n   - Document the current permission level (Read and write permissions vs. Read repository contents and packages permissions)\n   - Check if \"Allow GitHub Actions to create and approve pull requests\" is enabled\n4. Assess the security impact:\n   - Determine if permissions were expanded (potentially dangerous) or restricted (potentially disruptive)\n   - Review recent workflow runs across the organization for any suspicious activity\n   - Check for any new or modified workflows that may have been added around the time of this change\n5. If unauthorized or suspicious:\n   - Immediately revert the permissions to the previous secure state\n   - Review GitHub audit logs for other suspicious activities by the same actor\n   - Check for any workflows that executed between the permission change and reversion\n   - Rotate any secrets that may have been exposed\n   - Consider revoking the actor's admin privileges pending investigation\n   - Review all recent commits and pull requests for signs of compromise\n6. Implement preventive measures:\n   - Enable branch protection rules requiring reviews for workflow file changes\n   - Implement the principle of least privilege for workflow permissions at the repository level\n   - Consider using environment protection rules for sensitive deployments\n   - Enable secret scanning and push protection\n   - Document approved workflow permission settings in your security policies\n"
    default_reference = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"

    def rule(self, event):
        return event.get("action") == "org.set_default_workflow_permissions" and event.get("operation_type") == "modify"

    def title(self, event):
        return f"Workflow permission settings for GITHUB_TOKENs have been changed for your organization [{event.get('org')}] by user [{event.get('actor')}]"

    tests = [
        RuleTest(
            name="Workflow Permissions Modified",
            expected_result=True,
            log={
                "p_any_actor_ids": ["12345678"],
                "p_any_usernames": ["homersimpson"],
                "p_event_time": "2025-10-15 18:41:19.605000000",
                "p_log_type": "GitHub.Audit",
                "p_parse_time": "2025-10-15 18:54:06.098589038",
                "p_source_label": "AuditLog",
                "p_udm": {"user": {"name": "homersimpson", "provider_id": "12345678"}},
                "_document_id": "2bY2MKh36kTq5SWjmj5__Q",
                "action": "org.set_default_workflow_permissions",
                "actor": "homersimpson",
                "actor_id": "12345678",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2025-10-15 18:41:19.605000000",
                "business": "yourcompany",
                "business_id": "1234",
                "created_at": "2025-10-15 18:41:19.605000000",
                "operation_type": "modify",
                "org": "YourCompany",
                "org_id": 123456780,
            },
        ),
        RuleTest(
            name="Workflow Permissions Created",
            expected_result=False,
            log={
                "p_any_actor_ids": ["12345678"],
                "p_any_usernames": ["homersimpson"],
                "p_event_time": "2025-10-15 18:41:19.605000000",
                "p_log_type": "GitHub.Audit",
                "p_parse_time": "2025-10-15 18:54:06.098589038",
                "p_source_label": "AuditLog",
                "p_udm": {"user": {"name": "homersimpson", "provider_id": "12345678"}},
                "_document_id": "2bY2MKh36kTq5SWjmj5__Q",
                "action": "org.set_default_workflow_permissions",
                "actor": "homersimpson",
                "actor_id": "12345678",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2025-10-15 18:41:19.605000000",
                "business": "yourcompany",
                "business_id": "1234",
                "created_at": "2025-10-15 18:41:19.605000000",
                "operation_type": "create",
                "org": "YourCompany",
                "org_id": 123456780,
            },
        ),
    ]
