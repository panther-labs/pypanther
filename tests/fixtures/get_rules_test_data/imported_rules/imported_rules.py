from pypanther.base import Rule
from tests.fixtures.get_rules_test_data.some_other_module.some_other_module import SomeRule


class ImportedRule(Rule):
    """This rule is imported from another module"""

    id = "IMPORTED_RULE"
    enabled = SomeRule.enabled
