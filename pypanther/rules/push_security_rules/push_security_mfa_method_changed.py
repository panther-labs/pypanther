from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

push_security_mfa_method_changed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="All MFA methods removed",
        ExpectedResult=True,
        Log={
            "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
            "new": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": [],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "object": "ACCOUNT",
            "old": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "timestamp": 1707775049.0,
            "type": "CREATE",
            "version": "1",
        },
    ),
    PantherRuleTest(
        Name="First seen",
        ExpectedResult=False,
        Log={
            "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
            "new": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS", "APP_OTP"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "object": "ACCOUNT",
            "old": None,
            "timestamp": 1707775049.0,
            "type": "CREATE",
            "version": "1",
        },
    ),
    PantherRuleTest(
        Name="MFA method added",
        ExpectedResult=True,
        Log={
            "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
            "new": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS", "APP_OTP"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "object": "ACCOUNT",
            "old": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "timestamp": 1707775049.0,
            "type": "CREATE",
            "version": "1",
        },
    ),
    PantherRuleTest(
        Name="No MFA method change",
        ExpectedResult=False,
        Log={
            "id": "d1e5794f-666d-4cba-abae-c6d889ca1903",
            "new": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS", "APP_OTP"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "object": "ACCOUNT",
            "old": {
                "appId": "67ef5c13-b5e6-4945-af7b-c11ac98f630f",
                "appType": "CONTENTFUL",
                "creationTimestamp": 1707775048.0,
                "email": "jet.black@issp.com",
                "employeeId": "ca6cf7ce-90e6-4eb5-a262-7899bc48c39c",
                "id": "5e15ce4c-6b93-4fbf-aed9-1890775efa90",
                "lastUsedTimestamp": None,
                "loginMethods": {
                    "oidcLogin": None,
                    "oktaSwaLogin": False,
                    "passwordLogin": False,
                    "samlLogin": None,
                },
                "mfaMethods": ["SMS", "APP_OTP"],
                "mfaRegistered": False,
                "passwordId": None,
            },
            "timestamp": 1707775049.0,
            "type": "CREATE",
            "version": "1",
        },
    ),
]


class PushSecurityMFAMethodChanged(PantherRule):
    RuleID = "Push.Security.MFA.Method.Changed-prototype"
    DisplayName = "Push Security SaaS App MFA Method Changed"
    LogTypes = [LogType.PushSecurity_Entities]
    Severity = PantherSeverity.Info
    Description = "MFA method on SaaS app changed"
    Tests = push_security_mfa_method_changed_tests

    def rule(self, event):
        if event.get("object") != "ACCOUNT":
            return False
        if event.get("old") is None:
            return False
        new_mfa_methods = set(event.deep_get("new", "mfaMethods"))
        old_mfa_methods = set(event.deep_get("old", "mfaMethods", default=[]))
        if new_mfa_methods != old_mfa_methods:
            return True
        return False

    def severity(self, event):
        if event.deep_get("new", "mfaMethods") == []:
            return "HIGH"
        return "LOW"

    def title(self, event):
        mfa_methods = ", ".join(event.deep_get("new", "mfaMethods", default="No MFA"))
        new_email = event.deep_get("new", "email")
        new_apptype = event.deep_get("new", "appType")
        if mfa_methods == "":
            return f"{new_email} removed all MFA methods on {new_apptype}"
        return f"{new_email} changed MFA method to {mfa_methods} on {new_apptype}"
