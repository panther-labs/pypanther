"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import re
from typing import Any, Callable, Tuple

from pypanther import display
from pypanther.backend.client import Client as BackendClient
from pypanther.backend.public_api_client import PublicAPIClient, PublicAPIClientOptions
from pypanther.constants import PANTHER_USER_ID

UNKNOWN_VERSION = "unknown"


class BackendNotFoundException(Exception):
    pass


def func_with_backend(
    func: Callable[[BackendClient, argparse.Namespace], Any],
) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    return lambda args: func(get_backend(args), args)


def get_backend(args: argparse.Namespace) -> BackendClient:
    if not args.api_token:
        raise BackendNotFoundException("API token is required")

    verbose = args.verbose if hasattr(args, "verbose") else False
    output_type = args.output if hasattr(args, "output") else display.OUTPUT_TYPE_TEXT
    return PublicAPIClient(
        PublicAPIClientOptions(
            token=args.api_token,
            user_id=PANTHER_USER_ID,
            host=args.api_host,
            verbose=verbose,
            output_type=output_type,
        ),
    )


def convert_unicode(obj: Any) -> str:
    """
    Swap unicode 4 byte strings with arbitrary numbers of leading slashes with the actual character
    e.g. \\\\u003c => <
    """
    string_to_convert = str(obj)
    return re.sub(r"\\*\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), string_to_convert)
