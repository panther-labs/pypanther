from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubSecretScanningAlertCreated(Rule):
    id = "GitHub.Secret.Scanning.Alert.Created-prototype"
    display_name = "GitHub Secret Scanning Alert Created"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.MEDIUM
    default_description = "GitHub detected a secret and created a secret scanning alert."
    default_runbook = "Review the secret to determine if it needs to be revoked or the alert suppressed."
    default_reference = "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"

    def rule(self, event):
        return event.get("action", "") == "secret_scanning_alert.create"

    def title(self, event):
        return f"Github detected a secret in {event.get('repo', '<REPO_NOT_FOUND>')} (#{event.get('number', '<NUMBER_NOT_FOUND>')})"

    def alert_context(self, event):
        return {
            "github_organization": event.get("org", "<ORG_NOT_FOUND>"),
            "github_repository": event.get("repo", "<REPO_NOT_FOUND>"),
            "alert_number": str(event.get("number", "<NUMBER_NOT_FOUND>")),
            "url": f"https://github.com/{event.get('repo')}/security/secret-scanning/{event.get('number')}"
            if all([event.get("repo"), event.get("number")])
            else "<URL_NOT_FOUND>",
        }

    tests = [
        RuleTest(
            name="secret_scanning_alert.create-true",
            expected_result=True,
            log={
                "action": "secret_scanning_alert.create",
                "actor": "github",
                "actor_id": "1234",
                "business": "Acme Inc.",
                "business_id": "12345",
                "created_at": "2023-10-18 18:20:52.209000000",
                "number": 12,
                "org": "acme-inc",
                "org_id": 1234567,
                "repo": "acme-inc/crown-jewels",
                "repo_id": 123456789,
            },
        ),
        RuleTest(
            name="git.clone-false",
            expected_result=False,
            log={
                "_document_id": "KCYtigpnShPBSohA4OXbRg==",
                "action": "git.clone",
                "actor": "acme-inc-user",
                "actor_id": "123456789",
                "actor_ip": "5.6.7.8",
                "actor_location": {"country_code": "US"},
                "at_sign_timestamp": "2023-11-20 21:20:09.423",
                "business": "acme-inc",
                "business_id": "12345",
                "external_identity_nameid": "",
                "external_identity_username": "",
                "hashed_token": "0771cae4d170dc02a6ff393d9946cd684d6145c1=",
                "org": "acme-inc",
                "org_id": 12345678,
                "programmatic_access_type": "OAuth access token",
                "repo": "acme-inc/a-repo",
                "repository": "acme-inc/a-repo",
                "repository_public": False,
                "token_id": "0123456789",
                "transport_protocol": 1,
                "transport_protocol_name": "http",
                "user": "",
                "user_agent": "git/2.30.2",
                "user_id": "0",
            },
        ),
    ]
