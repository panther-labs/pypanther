from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gsuite import gsuite_activityevent_alert_context


@panther_managed
class GSuiteGmailMaliciousSMTPResponse(Rule):
    id = "GSuite.Gmail.Malicious.SMTP.Response-prototype"
    display_name = "Gmail Malicious SMTP Response"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Gmail", "Email Security", "Malware", "Spam"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566"]}
    default_severity = Severity.HIGH
    status = "Experimental"
    default_description = "Detects when Gmail blocks or rejects emails due to malicious SMTP response reasons including malware detection, spam/phishing links, low sender reputation, RBL listings, or denial of service attempts. This rule monitors inbound SMTP connections for security threats that Gmail's filters identify.\n"
    default_reference = "https://support.google.com/a/answer/12384955"
    default_runbook = "1. Review the sender's email address and domain\n2. Check the SMTP response reason and reply code for details\n3. Investigate the sender's IP address for additional context (geolocation, reputation)\n4. Review authentication status (SPF, DKIM, DMARC)\n5. If malware was detected, check if similar messages were received by other users\n6. Consider adding sender to blocklist if pattern of malicious activity is confirmed\n7. For DoS attempts, review firewall and rate limiting configurations\n"
    summary_attributes = ["user_email", "sender_address", "smtp_response_reason"]
    # SMTP response reasons that indicate security threats
    MALICIOUS_SMTP_RESPONSES = {
        3: "Malware",
        13: "Blatant Spam",
        14: "Denial of Service",
        15: "Malicious or Spam Links",
        16: "Low IP Reputation",
        17: "Low Domain Reputation",
        18: "IP address listed in public real-time block list",
    }

    def rule(self, event):
        if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
            return False
        smtp_response_reason = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "smtp_response_reason",
            default=0,
        )
        return smtp_response_reason in self.MALICIOUS_SMTP_RESPONSES

    def title(self, event):
        user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
        smtp_response_reason = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "smtp_response_reason",
            default=0,
        )
        reason_description = self.MALICIOUS_SMTP_RESPONSES.get(
            smtp_response_reason,
            f"Unknown ({smtp_response_reason})",
        )
        sender = event.deep_get("parameters", "message_info", "source", "address", default="<UNKNOWN_SENDER>")
        return f"Gmail blocked email to [{user}] from [{sender}] due to: {reason_description}"

    def alert_context(self, event):
        context = gsuite_activityevent_alert_context(event)
        # Add specific SMTP response information
        smtp_response_reason = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "smtp_response_reason",
            default=0,
        )
        context.update(
            {
                "smtp_response_reason_code": smtp_response_reason,
                "smtp_response_reason": self.MALICIOUS_SMTP_RESPONSES.get(
                    smtp_response_reason,
                    f"Unknown ({smtp_response_reason})",
                ),
                "smtp_reply_code": event.deep_get(
                    "parameters",
                    "message_info",
                    "connection_info",
                    "smtp_reply_code",
                    default=0,
                ),
            },
        )
        return context

    tests = [
        RuleTest(
            name="Malware Detected",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_event_time": "2025-11-04 20:44:43.248000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "frodo@lotr.com", "profileId": "123456789"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-04 20:44:43.248000000",
                    "uniqueQualifier": "-123456789",
                },
                "ipAddress": "1.1.1.1",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 368746, "timestamp_usec": 1730751883248347, "success": False},
                    "message_info": {
                        "action_type": 2,
                        "source": {"address": "eve@lexcorp.com", "from_header_address": "eve@lexcorp.com"},
                        "destination": [{"address": "frodo@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "1.1.1.1",
                            "is_internal": False,
                            "smtp_response_reason": 3,
                            "smtp_reply_code": 550,
                            "dkim_pass": False,
                            "spf_pass": False,
                            "dmarc_pass": False,
                            "ip_geo_country": "XX",
                        },
                        "subject": "Invoice Attached - Please Review",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Blatant Spam",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_event_time": "2025-11-04 21:10:15.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "denethor@lotr.com", "profileId": "987654321"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-04 21:10:15.000000000",
                    "uniqueQualifier": "-987654321",
                },
                "ipAddress": "1.2.3.4",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 250000, "timestamp_usec": 1730753415000000, "success": False},
                    "message_info": {
                        "action_type": 2,
                        "source": {"address": "john@justice.org", "from_header_address": "john@justice.org"},
                        "destination": [{"address": "denethor@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "1.2.3.4",
                            "is_internal": False,
                            "smtp_response_reason": 13,
                            "smtp_reply_code": 550,
                            "dkim_pass": False,
                            "spf_pass": True,
                            "dmarc_pass": False,
                        },
                        "subject": "WINNER!!! Claim your prize NOW!!!",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Normal Email - Should Not Alert",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["172.16.0.10"],
                "p_event_time": "2025-11-04 20:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "gimli@lotr.com", "profileId": "123456789"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-04 20:00:00.000000000",
                    "uniqueQualifier": "-123456789",
                },
                "ipAddress": "172.16.0.10",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 100000, "timestamp_usec": 1730750400000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {
                            "address": "clark@justice.org",
                            "from_header_address": "colleague@partner-company.com",
                        },
                        "destination": [{"address": "gimli@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "172.16.0.10",
                            "is_internal": False,
                            "smtp_response_reason": 1,
                            "smtp_reply_code": 250,
                            "dkim_pass": True,
                            "spf_pass": True,
                            "dmarc_pass": True,
                        },
                        "subject": "Meeting Notes",
                    },
                },
                "type": "message_delivery",
            },
        ),
    ]
