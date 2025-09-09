import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubSupplyChainSuspiciousUserAgents(Rule):
    id = "GitHub.SupplyChain.SuspiciousUserAgents-prototype"
    display_name = "GitHub Supply Chain - Software Installation Tool User Agents"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["Supply Chain", "Installation Tools", "Package Managers"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002"]}
    default_severity = Severity.MEDIUM
    default_description = "Detects software installation tool user agents in GitHub audit logs that should never  directly access GitHub. Package managers like npm, pip, yarn, and system installers  operate at the registry level, not GitHub audit level. Their presence indicates: 1. Supply chain attacks using spoofed user agents to blend in 2. Compromised systems running installation tools with stolen GitHub tokens   3. Malicious automation disguised as legitimate package managers\nBased on analysis of GitHub audit logs showing zero legitimate npm/yarn/pip user agents, any such patterns are inherently suspicious and warrant immediate investigation.\n"
    default_runbook = "1. Verify the actor and IP address associated with the activity 2. Check if the GitHub token/credentials used have been compromised 3. Review all actions performed by this user agent for malicious activity 4. Investigate if this represents a supply chain attack or credential theft 5. Consider revoking affected tokens and resetting credentials 6. Review repository access and recent changes for signs of compromise\n"
    default_reference = "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization"
    # pylint: disable=line-too-long
    # Suspicious package manager and installation tool patterns
    # NPM patterns
    # https://github.com/npm/cli/blob/latest/workspaces/config/lib/definitions/definitions.js#L2137
    # Format: npm/{version} node/v{version} {platform} {arch} workspaces/{boolean} [ci/{name}]
    # Yarn patterns
    # https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/scriptUtils.ts#L187-L192
    # "yarn/{version} npm/? node/{version} {platform} {arch}"
    # Python pip patterns
    # https://github.com/pypa/pip/blob/main/src/pip/_internal/network/session.py#L204
    # "pip/24.0 {"ci":null,"cpu":"aarch64","distro":{"name":"Alpine Linux"...}}"
    # Ruby Gem patterns
    # https://github.com/rubygems/rubygems/blob/master/lib/rubygems/request.rb#L276
    # Ruby, RubyGems/{version} {platform} Ruby/{version} ({date} patchlevel {number})
    # Rust Cargo patterns
    # https://github.com/rust-lang/cargo/blob/master/src/cargo/util/network/http.rs#L76
    # Default user agent: handle.useragent(&format!("cargo/{}", version()))?;
    SUSPICIOUS_PATTERNS = [
        "npm/\\d+\\.\\d+\\.\\d+\\s+node/v\\d+\\.\\d+\\.\\d+\\s+\\w+\\s+\\w+\\s+workspaces/(?:true|false)(?:\\s+ci/\\w+)?",
        "yarn/\\d+\\.\\d+\\.\\d+(?:-core)?\\s+npm/\\?\\s+node/v\\d+\\.\\d+\\.\\d+\\s+\\w+\\s+\\w+",
        "pip/\\d+\\.\\d+(?:\\.\\d+)?\\s+\\{.*\\}",
        "Ruby,\\s+RubyGems/\\d+\\.\\d+\\.\\d+\\s+[\\w-]+\\s+Ruby/\\d+\\.\\d+\\.\\d+\\s+\\([^)]+\\)",
        "cargo/\\d+\\.\\d+\\.\\d+",
    ]
    # Compile regex patterns for performance
    COMPILED_SUSPICIOUS_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS]

    def rule(self, event):
        user_agent = event.get("user_agent", "")
        action = event.get("action", "")
        # Allow legitimate dependency installation actions
        legitimate_actions = {"git.clone", "git.fetch", "git.pull", "git.checkout", "git.archive", "repo.download"}
        if action in legitimate_actions:
            return False
        if not user_agent or len(user_agent) < 3:
            return False
        for compiled_pattern in self.COMPILED_SUSPICIOUS_PATTERNS:
            match = compiled_pattern.search(user_agent)
            if match:
                return True
        return False

    def title(self, event):
        user_agent = event.get("user_agent", "")
        action = event.get("action", "")
        detected_pattern = "unknown"
        for compiled_pattern in self.COMPILED_SUSPICIOUS_PATTERNS:
            match = compiled_pattern.search(user_agent)
            if match:
                detected_pattern = match.group()
        return f"GitHub Supply Chain - Package Manager Modifying Repository ({detected_pattern} - {action})"

    def alert_context(self, event):
        context = github_alert_context(event)
        user_agent = event.get("user_agent", "")
        detected_pattern = "unknown"
        for compiled_pattern in self.COMPILED_SUSPICIOUS_PATTERNS:
            match = compiled_pattern.search(user_agent)
            if match:
                detected_pattern = match.group()
        context.update(
            {
                "user_agent": user_agent,
                "detected_pattern": detected_pattern,
                "user_agent_length": len(user_agent),
                "programmatic_access_type": event.get("programmatic_access_type"),
                "action": event.get("action"),
                "repo": event.get("repo"),
                "analysis_note": "Package managers should only read dependencies, not modify repositories",
            },
        )
        return context

    def dedup(self, event):
        user_agent = event.get("user_agent", "")
        actor = event.get("actor", "<NO_ACTOR>")
        return f"{user_agent}_{actor}"

    tests = [
        RuleTest(
            name="NPM User Agent - Malicious Repository Modification",
            expected_result=True,
            log={
                "action": "repo.update",
                "user_agent": "npm/10.2.4 node/v18.19.0 linux x64 workspaces/false",
                "actor": "malicious-actor",
                "repo": "organization/sensitive-repo",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Yarn User Agent - Suspicious Package Installation",
            expected_result=True,
            log={
                "action": "repo.create",
                "user_agent": "yarn/3.6.4-core npm/? node/v20.10.0 darwin arm64",
                "actor": "suspicious-user",
                "repo": "organization/new-malicious-repo",
                "programmatic_access_type": "github_app",
            },
        ),
        RuleTest(
            name="Python Pip User Agent - Repository Access",
            expected_result=True,
            log={
                "action": "repo.access",
                "user_agent": 'pip/24.0 {"ci":null,"cpu":"aarch64","distro":{"name":"Alpine Linux"}}',
                "actor": "automated-bot",
                "repo": "organization/python-project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Ruby Gem User Agent - File Modification",
            expected_result=True,
            log={
                "action": "git.push",
                "user_agent": "Ruby, RubyGems/3.4.22 linux-x86_64 Ruby/3.1.4 (2023-03-30 patchlevel 223)",
                "actor": "gem-installer",
                "repo": "organization/ruby-app",
                "programmatic_access_type": "deploy_key",
            },
        ),
        RuleTest(
            name="Rust Cargo User Agent - Repository Clone",
            expected_result=True,
            log={
                "action": "repo.destroy",
                "user_agent": "cargo/1.75.0",
                "actor": "cargo-user",
                "repo": "organization/rust-project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Legitimate Git Clone Action - Should Not Alert",
            expected_result=False,
            log={
                "action": "git.clone",
                "user_agent": "npm/10.2.4 node/v18.19.0 linux x64 workspaces/false",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Legitimate Git Fetch Action - Should Not Alert",
            expected_result=False,
            log={
                "action": "git.fetch",
                "user_agent": "yarn/3.6.4-core npm/? node/v20.10.0 darwin arm64",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Normal Web Browser User Agent - Should Not Alert",
            expected_result=False,
            log={
                "action": "repo.update",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "oauth_token",
            },
        ),
        RuleTest(
            name="GitHub CLI User Agent - Should Not Alert",
            expected_result=False,
            log={
                "action": "repo.create",
                "user_agent": "GitHub CLI 2.40.1",
                "actor": "developer",
                "repo": "organization/new-project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Git Command Line User Agent - Should Not Alert",
            expected_result=False,
            log={
                "action": "git.push",
                "user_agent": "git/2.39.3",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "deploy_key",
            },
        ),
        RuleTest(
            name="Empty User Agent - Should Not Alert",
            expected_result=False,
            log={
                "action": "repo.update",
                "user_agent": "",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Short User Agent - Should Not Alert",
            expected_result=False,
            log={
                "action": "repo.update",
                "user_agent": "ab",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Missing User Agent Field - Should Not Alert",
            expected_result=False,
            log={
                "action": "repo.update",
                "actor": "developer",
                "repo": "organization/project",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="NPM Pattern with CI - Malicious Action",
            expected_result=True,
            log={
                "action": "org.update_member",
                "user_agent": "npm/9.8.1 node/v18.17.1 linux x64 workspaces/true ci/github-actions",
                "actor": "malicious-ci",
                "repo": "organization/project",
                "programmatic_access_type": "github_app",
            },
        ),
        RuleTest(
            name="Yarn Pattern Variation - Different Version Format",
            expected_result=True,
            log={
                "action": "repo.transfer",
                "user_agent": "yarn/4.0.2 npm/? node/v21.2.0 win32 x64",
                "actor": "suspicious-transfer",
                "repo": "organization/valuable-repo",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Pip Pattern with Complex JSON - Repository Deletion",
            expected_result=True,
            log={
                "action": "repo.destroy",
                "user_agent": 'pip/23.3.1 {"implementation":{"name":"cpython","version":"3.11.6"},"system":{"name":"linux"}}',
                "actor": "malicious-pip",
                "repo": "organization/critical-infrastructure",
                "programmatic_access_type": "personal_access_token",
            },
        ),
        RuleTest(
            name="Case Insensitive Pattern Matching - Uppercase NPM",
            expected_result=True,
            log={
                "action": "repo.update",
                "user_agent": "NPM/10.2.4 NODE/V18.19.0 LINUX X64 WORKSPACES/FALSE",
                "actor": "case-test-actor",
                "repo": "organization/test-repo",
                "programmatic_access_type": "personal_access_token",
            },
        ),
    ]
