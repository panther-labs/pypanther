from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.log_types import LogType


class NotionLoginFromBlockedIP(PantherRule):
    RuleID = "Notion.LoginFromBlockedIP-prototype"
    DisplayName = "Notion Login From Blocked IP"
    Enabled = False
    LogTypes = [LogType.Notion_AuditLogs]
    Tags = [
        "Notion",
        "Network Security Monitoring",
        "Malicious Connections",
        "Configuration Required",
    ]
    Severity = PantherSeverity.Medium
    Description = "A user attempted to access Notion from a blocked IP address. Note: before deployinh, make sure to add Rule Filters checking if event.ip_address is in a certain CIDR range(s)."
    Runbook = (
        "Confirm with user if the login was legitimate. If so, determine why the IP is blocked."
    )
    Reference = "https://www.notion.so/help/allowlist-ip"

    def rule(self, event):
        # Users can specify inline-filters to permit rules based on IPs
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "user.login"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        ip_addr = event.deep_get("event", "ip_address", default="<UNKNOWN IP>")
        return f"Notion User [{user}] attempted to login from a blocked IP: [{ip_addr}]."

    def alert_context(self, event):
        return notion_alert_context(event)
