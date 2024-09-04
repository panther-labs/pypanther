from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class StandardMFADisabled(Rule):
    id = "Standard.MFADisabled-prototype"
    display_name = "MFA Disabled"
    log_types = [LogType.ATLASSIAN_AUDIT, LogType.GITHUB_AUDIT, LogType.ZENDESK_AUDIT, LogType.OKTA_SYSTEM_LOG]
    tags = ["DataModel", "Defense Evasion:Modify Authentication Process"]
    reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    default_reference = "https://en.wikipedia.org/wiki/Multi-factor_authentication"
    default_severity = Severity.HIGH
    default_description = "Detects when Multi-Factor Authentication (MFA) is disabled"
    summary_attributes = ["p_any_ip_addresses"]

    def rule(self, event):
        return event.udm("event_type") == event_type.MFA_DISABLED

    def title(self, event):
        # use unified data model field in title
        return f"{event.get('p_log_type')}: User [{event.udm('actor_user')}] disabled MFA"

    tests = [
        RuleTest(
            name="GitHub - Org MFA Disabled",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "org.disable_two_factor_requirement",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repository": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="GitHub - Org MFA Enabled",
            expected_result=False,
            log={
                "actor": "cat",
                "action": "org.enable_two_factor_requirement",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repository": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="Zendesk - Two-factor disabled",
            expected_result=True,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "account_setting",
                "source_label": "Two-Factor authentication for all admins and agents",
                "action": "create",
                "change_description": "Disabled",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Zendesk - Alternate Two-factor disabled",
            expected_result=True,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "account_setting",
                "source_label": "Require Two Factor",
                "action": "update",
                "change_description": "Disabled",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Zendesk - Two-factor Enabled",
            expected_result=False,
            log={
                "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
                "id": 123456789123,
                "action_label": "Updated",
                "actor_id": 123,
                "source_id": 123,
                "source_type": "account_setting",
                "source_label": "Require Two Factor",
                "action": "create",
                "change_description": "Enabled",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Okta - User resets own MFA ( INFO severity detection for this in Okta rules )",
            expected_result=False,
            log={
                "eventtype": "user.mfa.factor.deactivate",
                "version": "0",
                "severity": "INFO",
                "displaymessage": "Reset factor for user",
                "actor": {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "11111111111",
                    "type": "User",
                },
                "client": {
                    "device": "Computer",
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    },
                    "zone": "null",
                },
                "outcome": {"reason": "User reset FIDO_WEBAUTHN factor", "result": "SUCCESS"},
                "target": [
                    {
                        "alternateId": "homer@springfield.gov",
                        "displayName": "Homer Simpson",
                        "id": "1111111",
                        "type": "User",
                    },
                ],
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "1111111"},
                "p_log_type": "Okta.SystemLog",
            },
        ),
        RuleTest(
            name="Okta - User disables MFA",
            expected_result=True,
            log={
                "eventtype": "user.mfa.factor.deactivate",
                "version": "0",
                "severity": "INFO",
                "displaymessage": "Reset factor for user",
                "actor": {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "11111111111",
                    "type": "User",
                },
                "client": {
                    "device": "Computer",
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    },
                    "zone": "null",
                },
                "outcome": {"result": "SUCCESS"},
                "target": [
                    {
                        "alternateId": "homer@springfield.gov",
                        "displayName": "Homer Simpson",
                        "id": "1111111",
                        "type": "User",
                    },
                ],
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "1111111"},
                "p_log_type": "Okta.SystemLog",
            },
        ),
        RuleTest(
            name="Okta - MFA Enabled",
            expected_result=False,
            log={
                "eventtype": "user.mfa.factor.update",
                "version": "0",
                "severity": "INFO",
                "displaymessage": "Update factor for user",
                "actor": {
                    "alternateId": "homer@springfield.gov",
                    "displayName": "Homer Simpson",
                    "id": "11111111111",
                    "type": "User",
                },
                "client": {
                    "device": "Computer",
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    },
                    "zone": "null",
                },
                "outcome": {"reason": "User reset FIDO_WEBAUTHN factor", "result": "SUCCESS"},
                "target": [
                    {
                        "alternateId": "homer@springfield.gov",
                        "displayName": "Homer Simpson",
                        "id": "1111111",
                        "type": "User",
                    },
                ],
                "authenticationcontext": {"authenticationStep": 0, "externalSessionId": "1111111"},
                "p_log_type": "Okta.SystemLog",
            },
        ),
    ]
