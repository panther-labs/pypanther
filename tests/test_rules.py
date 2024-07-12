import json
from typing import Type

import pytest

from pypanther.base import PantherRule
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.get import get_panther_rules


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.RuleID)
def test_rule(rule: Type[PantherRule]):
    results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype, _validate_config=False)
    for result in results:
        assert result.Passed


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.RuleID)
def test_asdict(rule: Type[PantherRule]):
    d = rule().asdict()
    json.dumps(d, indent=4)


if __name__ == "__main__":
    pytest.main()
