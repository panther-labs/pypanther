from typing import Type

import pytest

from panther_analysis.base import PantherRule
from panther_analysis.cache import DATA_MODEL_CACHE
from panther_analysis.get import get_panther_rules


@pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.RuleID)
def test_rule(rule: Type[PantherRule]):
    rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)


if __name__ == "__main__":
    pytest.main()
