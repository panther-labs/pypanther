from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SublimeMessageFlagged(Rule):
    default_description = "Sublime flagged some messages as suspicious."
    display_name = "Sublime Flagged an Email"
    default_severity = Severity.HIGH
    log_types = [LogType.SUBLIME_MESSAGE_EVENT]
    id = "Sublime.Message.Flagged-prototype"

    def rule(self, event):
        return event.get("type") == "message.flagged"

    def alert_context(self, event):
        flagged_rules = event.deep_walk("data", "flagged_rules", "name", default=["<UNKNOWN_NAMES>"])
        return {"flagged_rules": flagged_rules}

    def title(self, event):
        rule_count = len(event.deep_get("data", "flagged_rules", default=[]))
        return f"Sublime flagged email message that matched {rule_count} Sublime rules"

    tests = [
        RuleTest(
            name="Message Flagged",
            expected_result=True,
            log={
                "p_source_file": {
                    "aws_s3_bucket": "audit.log.export",
                    "aws_s3_key": "sublime_platform_message_events/2024/09/24/164544Z-FPXIFG.json",
                },
                "p_any_sha256_hashes": ["fb8b46e3317ac7d5036c6b21517d363634293c6d4f6bf1b1e67548c80948a1c6"],
                "p_event_time": "2024-09-24 16:45:43.302769000",
                "p_log_type": "Sublime.MessageEvent",
                "p_parse_time": "2024-09-24 16:51:47.687095351",
                "p_row_id": "a23385494d57dfbbbdcbe4fa218101",
                "p_schema_version": 0,
                "p_source_id": "7e2a59aa-687e-430e-ae4a-81d3c0163f52",
                "p_source_label": "Sublime Real Logs",
                "p_udm": {},
                "created_at": "2024-09-24 16:45:43.302769000",
                "data": {
                    "flagged_rules": [
                        {
                            "id": "b0ab266f-8a12-4020-b165-e97bb1aacc42",
                            "name": "Credential phishing: Engaging language and other indicators (untrusted sender)",
                        },
                        {
                            "id": "a014f82e-f2d7-4058-adb1-36fc086de0b8",
                            "name": "Attachment: HTML smuggling with unescape",
                        },
                        {
                            "id": "e4866908-60fe-46f0-866e-84d412627006",
                            "name": "Headers: Zimbra mailer from a non-supported OS version",
                        },
                        {
                            "id": "5a9dc2cd-39f5-4814-95df-aa7614cc8bdd",
                            "name": "Impersonation: Human Resources with link or attachment and engaging language",
                        },
                        {
                            "id": "7988f1f5-5c95-42c2-9140-ead5a975918e",
                            "name": "Request for Quote or Purchase (RFQ|RFP) with HTML smuggling attachment",
                        },
                    ],
                    "message": {
                        "canonical_id": "fb8b46e3317ac7d5036c6b21517d363634293c6d4f6bf1b1e67548c80948a1c6",
                        "external_id": "b86b1e58-e9f8-4b55-8b54-1402f9f95e69",
                        "id": "019224ec-aba6-763d-bb2e-cd4cbd40a29f",
                        "mailbox": {"id": "624c8394-4fe2-4ba0-bd2b-86d2e503c614"},
                        "message_source_id": "91956379-c2f3-4c50-a410-3ba89fb8bc74",
                    },
                },
                "type": "message.flagged",
            },
        ),
    ]
