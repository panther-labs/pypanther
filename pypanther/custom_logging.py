import logging
import sys

from colorama import Fore, Style, init


class CustomFormatter(logging.Formatter):
    format_str = "[%(levelname)s][%(name)s]: %(message)s"

    FORMATS = {
        logging.DEBUG: format_str,
        logging.INFO: format_str,
        logging.WARNING: Fore.YELLOW + format_str + Style.RESET_ALL,
        logging.ERROR: Fore.RED + format_str + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + format_str + Style.RESET_ALL,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging():
    # setup logger and print version info as necessary
    if sys.stderr.isatty():
        init()
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(CustomFormatter())
        logger.addHandler(handler)
    else:
        logging.basicConfig(
            format="[%(levelname)s][%(name)s]: %(message)s",
            level=logging.INFO,
        )
