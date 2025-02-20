from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamAccountAdminGranted(Rule):
    id = "Snowflake.Stream.AccountAdminGranted-prototype"
    display_name = "Snowflake Account Admin Granted"
    log_types = [LogType.SNOWFLAKE_GRANTS_TO_USERS]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0004:T1078"]}
    default_description = "Detect when account admin is granted."
    tags = ["Snowflake", "[MITRE] Privilege Escalation", "[MITRE] Valid Accounts"]

    def rule(self, event):
        if event.get("DELETED_ON"):
            return False
        return "admin" in event.get("GRANTEE_NAME", "").lower()

    def title(self, event):
        source_name = event.get("p_source_label", "<UNKNOWN SNOWFLAKE SOURCE>")
        target = event.get("GRANTED_TO", "<UNKNOWN TARGET>")
        actor = event.get("GRANTED_BY", "<UNKNOWN ACTOR>")
        role = event.get("GRANTEE_NAME", "<UNKNOWN ROLE>")
        return f"{source_name}: {actor} granted role {role} to {target}"

    tests = [
        RuleTest(
            name="Admin Role Assigned",
            expected_result=True,
            log={
                "p_event_time": "2024-10-08 11:24:50.682000000",
                "p_log_type": "Snowflake.GrantsToUsers",
                "p_source_label": "Snowflake Prod",
                "CREATED_ON": "2024-10-08 11:24:50.682000000",
                "GRANTED_BY": "SNOWFLAKE",
                "GRANTED_TO": "APPLICATION_ROLE",
                "GRANTEE_NAME": "TRUST_CENTER_ADMIN",
            },
        ),
        RuleTest(
            name="Non-Admin Role Assigned",
            expected_result=False,
            log={
                "p_event_time": "2024-10-08 11:24:50.682000000",
                "p_log_type": "Snowflake.GrantsToUsers",
                "p_source_label": "Snowflake Prod",
                "CREATED_ON": "2024-10-08 11:24:50.682000000",
                "GRANTED_BY": "SNOWFLAKE",
                "GRANTED_TO": "APPLICATION_ROLE",
                "GRANTEE_NAME": "TRUST_CENTER_VIEWER",
            },
        ),
    ]
