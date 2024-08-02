import json
from typing import Type

import pytest

from pypanther.base import Rule
from pypanther.cache import data_model_cache
from pypanther.get import get_panther_rules


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
def test_rule(rule: Type[Rule]):
    if hasattr(rule, "_tests"):
        rule.tests = rule._tests

    for result in rule.run_tests(data_model_cache().data_model_of_logtype, _validate_config=False):
        assert result.passed


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
def test_asdict(rule: Type[Rule]):
    d = rule().asdict()
    json.dumps(d, indent=4)


if __name__ == "__main__":
    pytest.main()
