from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

one_login_auth_factor_removed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User removed an auth factor",
        ExpectedResult=True,
        Log={
            "event_type_id": "172",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "authentication_factor_description": "2FA Name",
        },
    ),
    PantherRuleTest(
        Name="User deactivated an otp deice",
        ExpectedResult=True,
        Log={
            "event_type_id": "24",
            "actor_user_id": 123456,
            "actor_user_name": "Bob Cat",
            "user_id": 123456,
            "user_name": "Bob Cat",
            "otp_device_name": "2FA Name",
        },
    ),
]


class OneLoginAuthFactorRemoved(PantherRule):
    RuleID = "OneLogin.AuthFactorRemoved-prototype"
    DisplayName = "OneLogin Authentication Factor Removed"
    LogTypes = [LogType.OneLogin_Events]
    Tags = [
        "OneLogin",
        "Identity & Access Management",
        "Defense Evasion:Modify Authentication Process",
    ]
    Reports = {"MITRE ATT&CK": ["TA0005:T1556"]}
    Severity = PantherSeverity.Low
    Description = "A user removed an authentication factor or otp device.\n"
    Reference = "https://onelogin.service-now.com/kb_view_customer.do?sysparm_article=KB0010426"
    Runbook = "Investigate whether this was an intentional action and if other multifactor devices exist.\n"
    SummaryAttributes = [
        "account_id",
        "event_type_id",
        "user_name",
        "user_id",
        "authentication_factor_description",
        "otp_device_name",
    ]
    Tests = one_login_auth_factor_removed_tests

    def rule(self, event):
        # verify this is a auth factor being removed
        # event id 24 is otp device deregistration
        # event id 172 is a user deleted an authentication factor
        return str(event.get("event_type_id")) == "24" or str(event.get("event_type_id")) == "172"

    def dedup(self, event):
        return event.get("user_name", "<UNKNOWN_USER>")

    def title(self, event):
        if str(event.get("event_type_id")) == "172":
            return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] removed an authentication factor [{event.get('authentication_factor_description', '<UNKNOWN_AUTH_FACTOR>')}]"
        return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] deactivated an otp device [{(event.get('otp_device_name', '<UNKNOWN_OTP_DEVICE>'),)}]"
