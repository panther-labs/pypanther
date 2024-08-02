import argparse
from typing import Any, Dict

from pypanther.vendor.panther_analysis_tool.constants import CONFIG_FILE


def setup_dynaconf() -> Dict[str, Any]:
    # defer loading to improve performance
    from dynaconf import Dynaconf, Validator

    config_file_settings_raw = Dynaconf(
        settings_file=CONFIG_FILE,
        envvar_prefix="PANTHER",
        validators=[
            Validator("API_TOKEN", is_type_of=str),
            Validator("API_HOST", is_type_of=str),
        ],
    )
    # Dynaconf stores its keys in ALL CAPS
    return {k.lower(): v for k, v in config_file_settings_raw.as_dict().items()}


def dynaconf_argparse_merge(argparse_dict: Dict[str, Any], config_file_settings: Dict[str, Any]) -> None:
    # Set up another parser w/ no defaults
    aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    for k in argparse_dict:
        arg_name = k.replace("_", "-")
        if isinstance(argparse_dict[k], bool):
            aux_parser.add_argument("--" + arg_name, action="store_true")
        else:
            aux_parser.add_argument("--" + arg_name)
    # cli_args only contains args that were passed in the command line
    cli_args, _ = aux_parser.parse_known_args()
    for key, value in config_file_settings.items():
        if key not in cli_args:
            argparse_dict[key] = value
