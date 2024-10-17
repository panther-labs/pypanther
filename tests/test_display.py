import textwrap

import pytest

from pypanther.base import LogType, Rule, Severity
from pypanther.display import print_rule_table, print_rules_as_csv, print_rules_as_json


def test_print_rule_table(capsys):
    # arrange
    rules = [
        type(
            "FRule",
            (Rule,),
            {
                "id": "FRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Array Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ARule",
            (Rule,),
            {
                "id": "ARule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Zoo Rule",
                "default_severity": Severity.INFO,
                "enabled": False,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ZRule",
            (Rule,),
            {
                "id": "ZRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Fandom Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
    ]
    exp = textwrap.dedent(
        """
        +-------+--------------+------------------+---------+
        |   id  | display_name | default_severity | enabled |
        +-------+--------------+------------------+---------+
        | FRule |  Array Rule  |       INFO       |   True  |
        | ZRule | Fandom Rule  |       INFO       |   True  |
        | ARule |   Zoo Rule   |       INFO       |  False  |
        +-------+--------------+------------------+---------+
        Total rules: 3
        +-------+--------------+------------------+---------+
        |   id  | display_name | default_severity | enabled |
        +-------+--------------+------------------+---------+
        | ARule |   Zoo Rule   |       INFO       |  False  |
        | FRule |  Array Rule  |       INFO       |   True  |
        | ZRule | Fandom Rule  |       INFO       |   True  |
        +-------+--------------+------------------+---------+
        Total rules: 3
        +-------+------------------+
        |   id  | default_severity |
        +-------+------------------+
        | ARule |       INFO       |
        | FRule |       INFO       |
        | ZRule |       INFO       |
        +-------+------------------+
        Total rules: 3
        +--------------+------------------+
        | display_name | default_severity |
        +--------------+------------------+
        |  Array Rule  |       INFO       |
        | Fandom Rule  |       INFO       |
        |   Zoo Rule   |       INFO       |
        +--------------+------------------+
        Total rules: 3
        +-------+-----------+------------------+---------+
        |   id  | log_types | default_severity | enabled |
        +-------+-----------+------------------+---------+
        | ARule |  AWS.ALB  |       INFO       |  False  |
        | FRule |  AWS.ALB  |       INFO       |   True  |
        | ZRule |  AWS.ALB  |       INFO       |   True  |
        +-------+-----------+------------------+---------+
    """,
    ).lstrip()

    # act
    print_rule_table(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="display_name")
    print_rule_table(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="id")
    print_rule_table(rules, attributes=["id", "default_severity"], sort_by="display_name")
    print_rule_table(rules, attributes=["display_name", "default_severity"])
    print_rule_table(rules, print_total=False)
    std = capsys.readouterr()
    pytest.maxDiff = None

    # assert
    assert std.out == exp
    assert std.err == ""


def test_print_rules_as_json(capsys):
    # arrange
    rules = [
        type(
            "FRule",
            (Rule,),
            {
                "id": "FRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Array Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ARule",
            (Rule,),
            {
                "id": "ARule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Zoo Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ZRule",
            (Rule,),
            {
                "id": "ZRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Fandom Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
    ]
    exp = textwrap.dedent(
        """
        {
          "rules": [
            {
              "id": "FRule",
              "display_name": "Array Rule",
              "default_severity": "INFO",
              "enabled": true
            },
            {
              "id": "ZRule",
              "display_name": "Fandom Rule",
              "default_severity": "INFO",
              "enabled": true
            },
            {
              "id": "ARule",
              "display_name": "Zoo Rule",
              "default_severity": "INFO",
              "enabled": true
            }
          ],
          "total_rules": 3
        }
        {
          "rules": [
            {
              "id": "ARule",
              "display_name": "Zoo Rule",
              "default_severity": "INFO",
              "enabled": true
            },
            {
              "id": "FRule",
              "display_name": "Array Rule",
              "default_severity": "INFO",
              "enabled": true
            },
            {
              "id": "ZRule",
              "display_name": "Fandom Rule",
              "default_severity": "INFO",
              "enabled": true
            }
          ],
          "total_rules": 3
        }
        {
          "rules": [
            {
              "id": "ARule",
              "default_severity": "INFO"
            },
            {
              "id": "FRule",
              "default_severity": "INFO"
            },
            {
              "id": "ZRule",
              "default_severity": "INFO"
            }
          ],
          "total_rules": 3
        }
        {
          "rules": [
            {
              "display_name": "Array Rule",
              "default_severity": "INFO"
            },
            {
              "display_name": "Fandom Rule",
              "default_severity": "INFO"
            },
            {
              "display_name": "Zoo Rule",
              "default_severity": "INFO"
            }
          ],
          "total_rules": 3
        }
    """,
    ).lstrip()

    # act
    print_rules_as_json(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="display_name")
    print_rules_as_json(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="id")
    print_rules_as_json(rules, attributes=["id", "default_severity"], sort_by="display_name")
    print_rules_as_json(rules, attributes=["display_name", "default_severity"])
    std = capsys.readouterr()
    pytest.maxDiff = None

    # assert
    assert std.out == exp
    assert std.err == ""


def test_print_rules_as_csv(capsys):
    # arrange
    rules = [
        type(
            "FRule",
            (Rule,),
            {
                "id": "FRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Array Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ARule",
            (Rule,),
            {
                "id": "ARule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Zoo Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
        type(
            "ZRule",
            (Rule,),
            {
                "id": "ZRule",
                "log_types": [LogType.AWS_ALB],
                "display_name": "Fandom Rule",
                "default_severity": Severity.INFO,
                "enabled": True,
                "create_alert": True,
                "rule": lambda self, event: True,
            },
        ),
    ]
    exp = textwrap.dedent(
        """
        id,display_name,default_severity,enabled
        FRule,Array Rule,INFO,True
        ZRule,Fandom Rule,INFO,True
        ARule,Zoo Rule,INFO,True
        id,display_name,default_severity,enabled
        ARule,Zoo Rule,INFO,True
        FRule,Array Rule,INFO,True
        ZRule,Fandom Rule,INFO,True
        id,default_severity
        ARule,INFO
        FRule,INFO
        ZRule,INFO
        display_name,default_severity
        Array Rule,INFO
        Fandom Rule,INFO
        Zoo Rule,INFO
    """,
    ).lstrip()

    # act
    print_rules_as_csv(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="display_name")
    print_rules_as_csv(rules, attributes=["id", "display_name", "default_severity", "enabled"], sort_by="id")
    print_rules_as_csv(rules, attributes=["id", "default_severity"], sort_by="display_name")
    print_rules_as_csv(rules, attributes=["display_name", "default_severity"])
    std = capsys.readouterr()
    pytest.maxDiff = None

    # assert
    assert std.out == exp
    assert std.err == ""
