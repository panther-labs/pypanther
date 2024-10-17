from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubAdvancedSecurityChange(Rule):
    id = "GitHub.Advanced.Security.Change-prototype"
    display_name = "GitHub Security Change, includes GitHub Advanced Security"
    create_alert = False
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.LOW
    default_description = "The rule alerts when GitHub Security tools (Dependabot, Secret Scanner, etc) are disabled."
    default_runbook = "Confirm with GitHub administrators and re-enable the tools as applicable."
    default_reference = "https://docs.github.com/en/code-security/getting-started/auditing-security-alerts"
    # List of actions in markdown format
    # pylint: disable=line-too-long
    # https://github.com/github/docs/blob/main/content/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise.md
    # grep '^| `' audit-log-events-for-your-enterprise.md.txt | sed -e 's/\| //' -e 's/`//g' | awk -F\| '{if ($1 ~ /business/) {print $1}}'
    # pylint: enable=line-too-long
    # {GitHub Action: Alert Severity}
    # Bypass secret scanner push protection for a detected secret.
    # pylint: disable=line-too-long
    # The events that begin with "business" are seemingly from enterprise logs
    # business.disable_oidc  -  OIDC single sign-on was disabled for an enterprise.
    # business.disable_saml  -  SAML single sign-on was disabled for an enterprise.
    # business.disable_two_factor_requirement  -  The requirement for members to
    #    have two-factor authentication enabled to access an enterprise was disabled.
    # business.members_can_update_protected_branches.disable  -  The ability for
    #    enterprise members to update branch protection rules was disabled.
    #    Only enterprise owners can update protected branches.
    # business.referrer_override_disable  -  An enterprise owner or site administrator
    #    disabled the referrer policy override.
    # business_advanced_security.disabled  -  {% data
    #    variables.product.prodname_GH_advanced_security %}
    #    was disabled for your enterprise. For more information, see "[Managing
    #    {% data variables.product.prodname_GH_advanced_security %}
    #    features for your enterprise]
    #    (/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_advanced_security.disabled_for_new_repos  -  {% data
    #    variables.product.prodname_GH_advanced_security %} was disabled for
    #    new repositories in your enterprise. For more information, see
    #    "[Managing {% data variables.product.prodname_GH_advanced_security %} features
    #    for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_secret_scanning.disable  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_secret_scanning.disabled_for_new_repos  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_secret_scanning_custom_pattern_push_protection.disabled  -  Push protection for a custom pattern for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Defining custom patterns for {% data variables.product.prodname_secret_scanning %}](/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning#defining-a-custom-pattern-for-an-enterprise-account)."
    # business_secret_scanning_push_protection.disable  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_secret_scanning_push_protection.disabled_for_new_repos  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    # business_secret_scanning_push_protection_custom_message.disable  -  The custom message triggered by an attempted push to a push-protected repository was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    #
    # There are also correlating github _org_ level events
    # org.advanced_security_policy_selected_member_disabled - An enterprise owner prevented {% data variables.product.prodname_GH_advanced_security %} features from being enabled for repositories owned by the organization. {% data reusables.advanced-security.more-information-about-enforcement-policy %}
    # pylint: enable=line-too-long
    # repository_vulnerability_alerts.disable - Dependabot alerts was disabled.
    ADV_SEC_ACTIONS = {
        "dependabot_alerts.disable": "CRITICAL",
        "dependabot_alerts_new_repos.disable": "HIGH",
        "dependabot_security_updates.disable": "CRITICAL",
        "dependabot_security_updates_new_repos.disable": "HIGH",
        "repository_secret_scanning_push_protection.disable": "HIGH",
        "secret_scanning.disable": "CRITICAL",
        "secret_scanning_new_repos.disable": "HIGH",
        "bypass": "MEDIUM",
        "business.disable_oidc": "CRITICAL",
        "business.disable_saml": "CRITICAL",
        "business.disable_two_factor_requirement": "CRITICAL",
        "business.members_can_update_protected_branches.disable": "MEDIUM",
        "business.referrer_override_disable": "MEDIUM",
        "business_advanced_security.disabled": "CRITICAL",
        "business_advanced_security.disabled_for_new_repos": "HIGH",
        "business_secret_scanning.disable": "CRITICAL",
        "business_secret_scanning.disabled_for_new_repos": "CRITICAL",
        "business_secret_scanning_custom_pattern_push_protection.disabled": "HIGH",
        "business_secret_scanning_push_protection.disable": "CRITICAL",
        "business_secret_scanning_push_protection.disabled_for_new_repos": "HIGH",
        "business_secret_scanning_push_protection_custom_message.disable": "HIGH",
        "org.advanced_security_disabled_for_new_repos": "HIGH",
        "org.advanced_security_disabled_on_all_repos": "CRITICAL",
        "org.advanced_security_policy_selected_member_disabled": "HIGH",
        "repo.advanced_security_disabled": "CRITICAL",
        "repo.advanced_security_policy_selected_member_disabled": "HIGH",
        "repository_vulnerability_alerts.disable": "HIGH",
    }
    # Use the per action severity configured above

    def rule(self, event):
        return event.get("action", "") in self.ADV_SEC_ACTIONS

    def title(self, event):
        action = event.get("action", "")
        advanced_sec_text = ""
        # https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security#about-advanced-security-features
        if "advanced_security" in action or "secret_scanning" in action:
            advanced_sec_text = "Advanced "
        return f"Change detected to GitHub {advanced_sec_text}Security - {event.get('action', '')}"

    def alert_context(self, event):
        return github_alert_context(event)

    def severity(self, event):
        return self.ADV_SEC_ACTIONS.get(event.get("action", ""), "Low")

    def dedup(self, event):
        # 1. Actor
        # 2. Action
        # We should dedup on actor - action
        actor = event.get("actor", "<NO_ACTOR>")
        action = event.get("action", "<NO_ACTION>")
        return "_".join([actor, action])

    tests = [
        RuleTest(
            name="Secret Scanning Disabled on a Repo",
            expected_result=True,
            log={
                "action": "repository_secret_scanning_push_protection.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Secret Scanning Disabled Org Wide",
            expected_result=True,
            log={
                "action": "secret_scanning.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Secret Scanning Disabled for New Repos",
            expected_result=True,
            log={
                "action": "secret_scanning_new_repos.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Dependabot Alerts Disabled Org Wide",
            expected_result=True,
            log={
                "action": "dependabot_alerts.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Dependabot Alerts Disabled on New Repos",
            expected_result=True,
            log={
                "action": "dependabot_alerts_new_repos.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Dependabot Disabled Org Wide",
            expected_result=True,
            log={
                "action": "dependabot_security_updates.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Dependabot Disabled on New Repos",
            expected_result=True,
            log={
                "action": "dependabot_security_updates_new_repos.disable",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Non-GitHub Adv Sec Action",
            expected_result=False,
            log={
                "action": "enterprise.config.disable_anonymous_git_access",
                "actor": "bobert",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2022-08-16 16:56:49.309",
                "created_at": "2022-08-16 16:56:49.309",
                "org": "an-org",
                "repo": "an-org/a-repo",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Enterprise Log - business_advanced_security.enabled",
            expected_result=False,
            log={
                "@timestamp": 1671111111111,
                "_document_id": "gAcccccccccccccccccccc",
                "action": "business_advanced_security.enabled",
                "actor": "bobert",
                "actor_ip": "12.12.12.12",
                "actor_location": {"country_code": "US"},
                "business": "example-enterprise",
                "created_at": 1671111111111,
                "operation_type": "modify",
                "user": "bobert",
            },
        ),
        RuleTest(
            name="Enterprise Log - business_advanced_security.disabled",
            expected_result=True,
            log={
                "@timestamp": 1671111111111,
                "_document_id": "gAcccccccccccccccccccc",
                "action": "business_advanced_security.disabled",
                "actor": "bobert",
                "actor_ip": "12.12.12.12",
                "actor_location": {"country_code": "US"},
                "business": "example-enterprise",
                "created_at": 1671111111111,
                "operation_type": "modify",
                "user": "bobert",
            },
        ),
    ]
