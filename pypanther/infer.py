import argparse
import subprocess
from typing import Tuple

from pypanther import cli_output
from pkg_resources import resource_filename


def get_binary_path():
    return resource_filename("pypanther", "pantherlog")


def run(args: argparse.Namespace) -> Tuple[int, str]:
    binary_path = get_binary_path()

    if args is None:
        args = []

    # Run the binary and forward everything (letting the binary print to stdout)
    result = subprocess.run([str(binary_path), *args])
    return result.returncode, ""