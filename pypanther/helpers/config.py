"""Configuration values for Panther"""

from typing import Any

from pypanther.helpers import panther_config_defaults, panther_config_overrides


class Config:  # pylint: disable=too-few-public-methods
    def __getattr__(self, name) -> Any:
        if hasattr(panther_config_overrides, name):
            return getattr(panther_config_overrides, name)
        return getattr(panther_config_defaults, name, None)


config = Config()
