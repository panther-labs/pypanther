# PyPanther

[![PyPI version](https://badge.fury.io/py/pypanther.svg)](https://badge.fury.io/py/pypanther)
[![Python Versions](https://img.shields.io/pypi/pyversions/pypanther.svg)](https://pypi.org/project/pypanther/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE.txt)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**pypanther** is a Python framework for writing detection rules with Panther. It provides an intuitive interface for creating, managing, and deploying detections to enhance your security operations. Included is a `pypanther` CLI tool to interact with your content and upload it to a Panther instance.

## Features

- **Rule Creation**: Easily create rules using Python classes and inheritance
- **Type Safety**: Built with type hints for better IDE support and code quality
- **Testing Framework**: Built-in testing utilities for rule validation
- **CLI Tool**: Command-line interface for managing and deploying rules
- **Helper Functions**: Common security detection patterns and utilities
- **Log Type Support**: Native support for major cloud and security log types

## Installation

### From PyPI

To install **pypanther** from PyPI, use pip:

```bash
pip install pypanther
```

### From Source

To install from source:

```bash
git clone https://github.com/panther-labs/pypanther.git
cd pypanther
pip install -e .
```

### Development Setup

For development, we recommend using Poetry:

1. **Install Poetry**: Follow the instructions on the [Poetry website](https://python-poetry.org/docs/#installation) to install Poetry.

2. **Clone and Install**:
   ```bash
   git clone git@github.com:panther-labs/pypanther.git
   cd pypanther
   poetry install
   ```

3. **Activate the Environment**:
   ```bash
   poetry shell
   ```

## Prerequisites

- Python 3.11 or higher
- [Panther](https://panther.com) instance with API access
- Poetry (for development)

## Quick Start

Here is a simple `main.py` to get you started with development. Place this in the base directory:

```python
from pypanther import get_panther_rules, register
register(get_panther_rules())
```

```bash
$ poetry run pypanther list rules --log-types Panther.Audit
+-------------------------------------+---------------+------------------+---------+
|                  id                 |   log_types   | default_severity | enabled |
+-------------------------------------+---------------+------------------+---------+
| Panther.Detection.Deleted-prototype | Panther.Audit |       INFO       |   True  |
|   Panther.SAML.Modified-prototype   | Panther.Audit |       HIGH       |   True  |
|   Panther.Sensitive.Role-prototype  | Panther.Audit |       HIGH       |   True  |
|   Panther.User.Modified-prototype   | Panther.Audit |       HIGH       |   True  |
+-------------------------------------+---------------+------------------+---------+
```

For more detailed examples and implementation patterns, check out the [pypanther-starter-kit](https://github.com/panther-labs/pypanther-starter-kit).

## Documentation

- [User Guide](https://docs.panther.com/detections/pypanther)
- [Library Reference](https://docs.panther.com/detections/pypanther/library-reference)
- [CLI Guide](https://docs.panther.com/detections/pypanther/cli)
- [Rule Development Guide](https://docs.panther.com/detections/pypanther/creating)

## Development

### Running Tests

```bash
poetry run pytest
```

### Code Style

We use `ruff` for code formatting and linting, and `mypy` for type checking. To format and lint your code:

```bash
# Format code
poetry run ruff format .

# Check and fix imports
poetry run ruff check --select I --fix .

# Run all linting checks
poetry run ruff check --fix .

# Run type checking
poetry run mypy .
```

You can also use the provided Makefile commands:

```bash
# Format code and fix imports
make fmt

# Run all linting and type checking
make lint
```

### Development Guidelines

- Follow PEP 8 style guide
- Use `ruff` for code formatting and linting
- Use `mypy` for type checking
- Add tests for new features
- Update documentation as needed
- Keep commits clean and well-documented
- Add type hints to all new code

### Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Architecture

PyPanther is built with the following design principles:

- **Modularity**: Rules are self-contained and easily composable
- **Type Safety**: Comprehensive type hints for better development experience
- **Extensibility**: Easy to add new rule types and log sources
- **Testability**: Built-in testing framework for rule validation

## License

**pypanther** is released under [Apache License 2.0](LICENSE.txt).

## Acknowledgments

- Thanks to all our contributors
- Built with ❤️ by Panther Labs
