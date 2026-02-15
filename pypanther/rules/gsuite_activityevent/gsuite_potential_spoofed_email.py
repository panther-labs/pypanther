from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gsuite import gsuite_activityevent_alert_context


@panther_managed
class GSuiteGmailPotentialSpoofedEmail(Rule):
    id = "GSuite.Gmail.Potential.Spoofed.Email-prototype"
    display_name = "Gmail Potential Spoofed Email Delivered"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Gmail", "Email Security", "Spoofing", "Phishing"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566.001", "TA0001:T1566.002"]}
    default_severity = Severity.HIGH
    status = "Experimental"
    default_description = "Detects when a potentially spoofed email was successfully delivered to a user's inbox despite failing email authentication checks. This rule triggers when:\n1. DMARC authentication fails, OR 2. Both SPF and DKIM authentication fail simultaneously\nThese authentication failures indicate the sender may be impersonating a legitimate domain, which is a common tactic in phishing and business email compromise (BEC) attacks.\n"
    default_reference = "https://support.google.com/a/answer/12384955"
    default_runbook = "1. Review the sender's email address and compare with the From: header display name\n2. Check if the sender domain is impersonating an internal or partner domain\n3. Verify the authentication status details (SPF, DKIM, DMARC)\n4. Review the message subject and content if available\n5. Check the sender's IP geolocation and reputation\n6. Search for similar messages from the same sender to other users\n7. If confirmed as spoofing:\n   - Add sender domain/IP to blocklist\n   - Remove the message from user's inbox\n   - Notify affected users not to interact with the email\n8. Consider strengthening DMARC policy (quarantine/reject) if not already enforced\n"
    summary_attributes = ["user_email", "sender_address", "dmarc_pass", "spf_pass", "dkim_pass"]

    def rule(self, event):
        if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
            return False
        dmarc_passed = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "dmarc_pass",
            default="<UNKNOWN_DMARC_PASS>",
        )
        spf_passed = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "spf_pass",
            default="<UNKNOWN_SPF_PASS>",
        )
        dkim_passed = event.deep_get(
            "parameters",
            "message_info",
            "connection_info",
            "dkim_pass",
            default="<UNKNOWN_DKIM_PASS>",
        )
        event_success = event.deep_get("parameters", "event_info", "success", default=False)
        if event_success is True:  # Message was delivered despite failures
            if dmarc_passed is False:
                return True
            if spf_passed is False and dkim_passed is False:
                return True
        return False

    def title(self, event):
        user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
        return f"[{user}] received a potentially spoofed email"

    def alert_context(self, event):
        context = gsuite_activityevent_alert_context(event)
        return context

    tests = [
        RuleTest(
            name="DMARC Failed - Successfully Delivered",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["8.8.8.8"],
                "p_event_time": "2025-11-05 10:15:30.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "frodo@lotr.com", "profileId": "123456789"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 10:15:30.000000000",
                    "uniqueQualifier": "-123456789",
                },
                "ipAddress": "8.8.8.8",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 250000, "timestamp_usec": 1730800530000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {
                            "address": "john@justice.org",
                            "from_header_address": "john@justice.org",
                            "from_header_displayname": "CEO John Smith",
                        },
                        "destination": [{"address": "frodo@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "8.8.8.8",
                            "is_internal": False,
                            "dkim_pass": True,
                            "spf_pass": True,
                            "dmarc_pass": False,
                            "dmarc_published_domain": "fake-company.com",
                            "ip_geo_country": "RU",
                        },
                        "subject": "Urgent: Wire Transfer Request",
                        "rfc2822_message_id": "<denethor@lotr.com>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Both SPF and DKIM Failed - Successfully Delivered",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["7.7.7.7"],
                "p_event_time": "2025-11-05 11:30:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "legolas@lotr.com", "profileId": "987654321"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 11:30:00.000000000",
                    "uniqueQualifier": "-987654321",
                },
                "ipAddress": "7.7.7.7",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 180000, "timestamp_usec": 1730804980000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {
                            "address": "eve@lexcorp.com",
                            "from_header_address": "eve@lexcorp.com",
                            "from_header_displayname": "PayPal Support",
                        },
                        "destination": [{"address": "legolas@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "7.7.7.7",
                            "is_internal": False,
                            "dkim_pass": False,
                            "spf_pass": False,
                            "dmarc_pass": True,
                            "ip_geo_country": "CN",
                        },
                        "subject": "Your account has been suspended",
                        "rfc2822_message_id": "<john@justice.org>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="All Authentication Failed - Successfully Delivered",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["6.6.6.6"],
                "p_event_time": "2025-11-05 12:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "boromir@lotr.com", "profileId": "111222333"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 12:00:00.000000000",
                    "uniqueQualifier": "-111222333",
                },
                "ipAddress": "6.6.6.6",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 200000, "timestamp_usec": 1730806800000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {
                            "address": "denethor@lotr.com",
                            "from_header_address": "denethor@lotr.com",
                            "from_header_displayname": "Microsoft Billing",
                        },
                        "destination": [{"address": "boromir@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "6.6.6.6",
                            "is_internal": False,
                            "dkim_pass": False,
                            "spf_pass": False,
                            "dmarc_pass": False,
                            "ip_geo_country": "VN",
                        },
                        "subject": "Invoice Past Due - Immediate Action Required",
                        "rfc2822_message_id": "<eve@lexcorp.com>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Only SPF Failed - Should Not Alert (One Factor Pass)",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["5.5.5.5"],
                "p_event_time": "2025-11-05 13:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "denethor@lotr.com", "profileId": "444555666"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 13:00:00.000000000",
                    "uniqueQualifier": "-444555666",
                },
                "ipAddress": "5.5.5.5",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 150000, "timestamp_usec": 1730810400000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {"address": "bruce@justice.org", "from_header_address": "bruce@justice.org"},
                        "destination": [{"address": "denethor@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "5.5.5.5",
                            "is_internal": False,
                            "dkim_pass": True,
                            "spf_pass": False,
                            "dmarc_pass": True,
                            "ip_geo_country": "US",
                        },
                        "subject": "Monthly Newsletter",
                        "rfc2822_message_id": "<john@justice.org>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="All Authentication Passed - Should Not Alert",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["4.4.4.4"],
                "p_event_time": "2025-11-05 14:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "legolas@lotr.com", "profileId": "777888999"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 14:00:00.000000000",
                    "uniqueQualifier": "-777888999",
                },
                "ipAddress": "4.4.4.4",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 100000, "timestamp_usec": 1730814000000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {
                            "address": "gandalf@lotr.com",
                            "from_header_address": "gandalf@lotr.com",
                            "from_header_displayname": "Jane Doe",
                        },
                        "destination": [{"address": "legolas@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "4.4.4.4",
                            "is_internal": True,
                            "is_intra_domain": True,
                            "dkim_pass": True,
                            "spf_pass": True,
                            "dmarc_pass": True,
                            "ip_geo_country": "US",
                        },
                        "subject": "Project Update",
                        "rfc2822_message_id": "<gimli@lotr.com>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Authentication Failed But Message Blocked - Should Not Alert",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["3.3.3.3"],
                "p_event_time": "2025-11-05 15:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "boromir@lotr.com", "profileId": "222333444"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 15:00:00.000000000",
                    "uniqueQualifier": "-222333444",
                },
                "ipAddress": "3.3.3.3",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 120000, "timestamp_usec": 1730817600000000, "success": False},
                    "message_info": {
                        "action_type": 18,
                        "source": {"address": "frodo@lotr.com", "from_header_address": "frodo@lotr.com"},
                        "destination": [{"address": "boromir@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "3.3.3.3",
                            "is_internal": False,
                            "dkim_pass": False,
                            "spf_pass": False,
                            "dmarc_pass": False,
                            "smtp_reply_code": 550,
                            "smtp_response_reason": 4,
                            "ip_geo_country": "XX",
                        },
                        "subject": "Spoofing Attempt",
                        "rfc2822_message_id": "<denethor@lotr.com>",
                    },
                },
                "type": "message_delivery",
            },
        ),
        RuleTest(
            name="Non-Gmail Event - Should Not Alert",
            expected_result=False,
            log={
                "p_event_time": "2025-11-05 16:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "denethor@lotr.com", "profileId": "555666777"},
                "id": {
                    "applicationName": "drive",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 16:00:00.000000000",
                    "uniqueQualifier": "-555666777",
                },
                "ipAddress": "2.2.2.2",
                "kind": "admin#reports#activity",
                "name": "create",
                "type": "access",
            },
        ),
        RuleTest(
            name="Only DKIM Failed - Should Not Alert (Two Factors Pass)",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["172.16.0.30"],
                "p_event_time": "2025-11-05 17:00:00.000000000",
                "p_log_type": "GSuite.ActivityEvent",
                "actor": {"callerType": "USER", "email": "saruman@lotr.com", "profileId": "333444555"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "C01abc123",
                    "time": "2025-11-05 17:00:00.000000000",
                    "uniqueQualifier": "-333444555",
                },
                "ipAddress": "172.16.0.30",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 170000, "timestamp_usec": 1730825200000000, "success": True},
                    "message_info": {
                        "action_type": 2,
                        "source": {"address": "vendor@supplier.com", "from_header_address": "vendor@supplier.com"},
                        "destination": [{"address": "saruman@lotr.com", "service": "gmail-ui"}],
                        "connection_info": {
                            "client_ip": "172.16.0.30",
                            "is_internal": False,
                            "dkim_pass": False,
                            "spf_pass": True,
                            "dmarc_pass": True,
                            "ip_geo_country": "US",
                        },
                        "subject": "Purchase Order Confirmation",
                        "rfc2822_message_id": "<po12345@supplier.com>",
                    },
                },
                "type": "message_delivery",
            },
        ),
    ]
