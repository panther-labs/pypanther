import json
from typing import Type

import pytest

from pypanther.base import Rule
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.get import get_panther_rules


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
def test_rule(rule: Type[Rule]):
    results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
    for result in results:
        assert result.passed


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
def test_asdict(rule: Type[Rule]):
    d = rule().asdict()
    json.dumps(d, indent=4)


if __name__ == "__main__":
    pytest.main()
