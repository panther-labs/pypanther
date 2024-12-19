from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamPublicRoleGrant(Rule):
    id = "Snowflake.Stream.PublicRoleGrant-prototype"
    display_name = "Snowflake Grant to Public Role"
    log_types = [LogType.SNOWFLAKE_GRANTS_TO_ROLES]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0004:T1078.001"]}
    default_description = "Detect additional grants to the public role."
    default_runbook = (
        "Determine if this is a necessary grant for the public role, which should be kept to the fewest possible."
    )
    tags = [
        "Snowflake",
        "[MITRE] Privilege Escalation",
        "[MITRE] Valid Accounts",
        "[MITRE] Valid Accounts: Default Accounts",
    ]

    def rule(self, event):
        return event.get("GRANTEE_NAME").lower() == "public"

    def title(self, event):
        return f"{event.get('p_source_label', '<UNKNOWN LOG SOURCE>')}: {event.get('GRANTED_BY', '<UNKNWON ACTOR>')} made changes to the PUBLIC role"

    tests = [
        RuleTest(
            name="SELECT Granted to Public",
            expected_result=True,
            log={
                "p_source_label": "DailyPlanet-Snowflake",
                "CREATED_ON": "2024-10-10 12:56:35.822 -0700",
                "MODIFIED_ON": "2024-10-10 12:56:35.822 -0700",
                "PRIVILEGE": "SELECT",
                "GRANTED_ON": "TABLE",
                "NAME": "MYTABLE",
                "TABLE_CATALOG": "TEST_DB",
                "TABLE_SCHEMA": "PUBLIC",
                "GRANTED_TO": "ROLE",
                "GRANTEE_NAME": "PUBLIC",
                "GRANT_OPTION": False,
                "GRANTED_BY": "ACCOUNTADMIN",
                "DELETED_ON": "",
                "GRANTED_BY_ROLE_TYPE": "ROLE",
                "OBJECT_INSTANCE": "",
            },
        ),
        RuleTest(
            name="Privilege Granted to Non-PUBLIC Role",
            expected_result=False,
            log={
                "p_source_label": "DailyPlanet-Snowflake",
                "CREATED_ON": "2024-10-10 12:56:35.822 -0700",
                "MODIFIED_ON": "2024-10-10 12:56:35.822 -0700",
                "PRIVILEGE": "SELECT",
                "GRANTED_ON": "TABLE",
                "NAME": "MYTABLE",
                "TABLE_CATALOG": "TEST_DB",
                "TABLE_SCHEMA": "PUBLIC",
                "GRANTED_TO": "ROLE",
                "GRANTEE_NAME": "APP_READONLY",
                "GRANT_OPTION": False,
                "GRANTED_BY": "ACCOUNTADMIN",
                "DELETED_ON": "",
                "GRANTED_BY_ROLE_TYPE": "ROLE",
                "OBJECT_INSTANCE": "",
            },
        ),
    ]
