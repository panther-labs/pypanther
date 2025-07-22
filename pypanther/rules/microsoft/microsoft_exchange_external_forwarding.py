from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import is_external_address, m365_alert_context


@panther_managed
class Microsoft365ExchangeExternalForwarding(Rule):
    default_description = "Detects when a user creates email forwarding rules to external organizations in Microsoft Exchange Online. This can indicate data exfiltration attempts, where an attacker sets up forwarding to collect emails outside the organization. The rule detects both mailbox forwarding (Set-Mailbox) and inbox rules (New-InboxRule).\nThe detection includes: 1. External organization forwarding based on domain comparison 2. Suspicious forwarding patterns like:\n   - Forwarding without keeping a copy\n   - Deleting messages after forwarding\n   - Stopping rule processing after forwarding\n3. Multiple forwarding destinations 4. Various forwarding methods (SMTP, redirect, forward as attachment)\n"
    display_name = "Microsoft Exchange External Forwarding"
    reports = {"MITRE ATT&CK": ["TA0003:T1137.005", "TA0009:T1114.003", "TA0010:T1020"]}
    default_reference = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide"
    default_severity = Severity.HIGH
    tags = ["Microsoft365", "Exchange", "Data Exfiltration", "Email Security"]
    log_types = [LogType.MICROSOFT365_AUDIT_EXCHANGE]
    id = "Microsoft365.Exchange.External.Forwarding-prototype"
    summary_attributes = ["userid", "parameters", "organizationname"]
    default_runbook = "1. Investigate the forwarding configuration:\n   - Check if the forwarding is legitimate and approved\n   - Verify the destination addresses\n   - Review any suspicious patterns (deletion, no copy kept)\n2. If unauthorized:\n   - Remove the forwarding rule\n   - Check for any data that may have been forwarded\n   - Review the user's recent activity\n3. If authorized:\n   - Document the business justification\n   - Ensure it complies with security policies\n   - Monitor for any changes to the forwarding configuration\n"
    FORWARDING_PARAMETERS = {
        "ForwardingSmtpAddress",
        "ForwardTo",
        "ForwardingAddress",
        "RedirectTo",
        "ForwardAsAttachmentTo",
    }  # Only forward, don't keep copy
    # Delete after forwarding
    # Stop processing other rules
    SUSPICIOUS_PATTERNS = {
        "DeliverToMailboxAndForward": "False",
        "DeleteMessage": "True",
        "StopProcessingRules": "True",
    }

    def rule(self, event):
        """Alert on suspicious or external email forwarding configurations."""
        # Skip non-forwarding related operations
        if event.get("operation") not in ("Set-Mailbox", "New-InboxRule"):
            return False
        # Get organization domains from userid and organizationname
        onmicrosoft_domain = event.get("organizationname", "").lower()
        userid = event.get("userid", "").lower()
        try:
            primary_domain = userid.split("@")[1]
        except (IndexError, AttributeError):
            primary_domain = onmicrosoft_domain if onmicrosoft_domain else None
        if not primary_domain:
            return True  # Alert if we can't determine organization
        # Check each parameter
        for param in event.get("parameters", []):
            param_name = param.get("Name", "")
            param_value = param.get("Value", "")
            # Check for external forwarding
            if param_name in self.FORWARDING_PARAMETERS and param_value:
                if is_external_address(param_value, primary_domain, onmicrosoft_domain):
                    return True
        return False

    def title(self, event):
        parameters = event.get("parameters", [])
        forwarding_addresses = []
        suspicious_configs = []
        for param in parameters:
            param_name = param.get("Name", "")
            param_value = param.get("Value", "")
            if param_name in self.FORWARDING_PARAMETERS and param_value:
                # Handle smtp: prefix
                if param_value.lower().startswith("smtp:"):
                    param_value = param_value[5:]
                # Handle multiple addresses
                addresses = param_value.split(";")
                forwarding_addresses.extend(addr.strip() for addr in addresses if addr.strip())
            if param_name in self.SUSPICIOUS_PATTERNS and param_value == self.SUSPICIOUS_PATTERNS[param_name]:
                suspicious_configs.append(f"{param_name}={param_value}")
        to_emails = ", ".join(forwarding_addresses) if forwarding_addresses else "<no-recipient-found>"
        suspicious_str = f" [Suspicious: {', '.join(suspicious_configs)}]" if suspicious_configs else ""
        return f"Microsoft365: External Forwarding Created From [{event.get('userid', '')}] to [{to_emails}]{suspicious_str}"

    def severity(self, event):
        if not self.is_suspicious_pattern(event):
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event):
        return m365_alert_context(event)

    def is_suspicious_pattern(self, event):
        parameters = event.get("parameters", [])
        for param in parameters:
            param_name = param.get("Name", "")
            param_value = param.get("Value", "")
            if param_name in self.SUSPICIOUS_PATTERNS and param_value == self.SUSPICIOUS_PATTERNS[param_name]:
                return True
        return False

    tests = [
        RuleTest(
            name="External Organization Forwarding",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "homer.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:peter.griffin@familyguy.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Internal Organization Forwarding",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "marge.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:marge.simpson@simpsons.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Suspicious Forwarding Pattern",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "Delete and Forward Rule"},
                    {"Name": "Mailbox", "Value": "homer.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardTo", "Value": "external@example.com"},
                    {"Name": "DeleteMessage", "Value": "True"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Multiple Forwarding Addresses",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "Multiple Forward Rule"},
                    {"Name": "Mailbox", "Value": "homer.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardTo", "Value": "external1@example.com;external2@example.com;external3@example.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Invalid Identity Format",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "Invalid/Path/Format"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:hello@familyguy.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Missing Organization Name",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {
                        "Name": "Identity",
                        "Value": "ABC1.prod.outlook.com/Microsoft Exchange Hosted Organizations/simpsons.onmicrosoft.com/homer.simpson",
                    },
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:hello@familyguy.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Subdomain Forwarding (Internal)",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "homer.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:bart.simpson@springfield.simpsons.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Similar Domain Forwarding (External)",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "homer.simpson@simpsons.onmicrosoft.com"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:evil@simpsons2.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Non-Com TLD Organization",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "Identity", "Value": "homer.simpson@simpsons.org"},
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:marge.simpson@simpsons.org"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.org",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Internal Forwarding with Suspicious Pattern",
            expected_result=False,
            log={
                "clientip": "1.2.3.4:10736",
                "creationtime": "2025-07-07 09:11:11.000000000",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "ABC001.prod.outlook.com/Microsoft Exchange Hosted Organizations/simpsons.onmicrosoft.com/444-55-66\\Move GitHub emails",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
                    {"Name": "Force", "Value": "False"},
                    {"Name": "MoveToFolder", "Value": "MYFolder"},
                    {"Name": "Name", "Value": "Move emails to another folder"},
                    {"Name": "FromAddressContainsWords", "Value": "specialsender"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft",
                "userkey": "homer.simpson@simpsons.onmicrosoft",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
    ]
