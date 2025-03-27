# Contributing to PyPanther

Thank you for your interest in contributing to PyPanther! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:

- A clear title and description
- Steps to reproduce the issue
- Expected and actual behavior
- Any relevant logs or screenshots

### Suggesting Features

We welcome feature suggestions! When submitting a feature request:

- Provide a clear title and detailed description
- Explain why this feature would be useful to PyPanther users
- Suggest an implementation approach if possible

### Pull Requests

1. Fork the repository
2. Create a branch with a descriptive name
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Submit a pull request

### Pull Request Process

1. Update the README.md or documentation if necessary
2. Ensure all tests pass
3. Ensure code follows the project's style guidelines
4. Your PR should target the `main` branch

## Development Setup

We use [Poetry](https://python-poetry.org/) for dependency management and packaging.

1. **Install Poetry**:
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/panther-labs/pypanther.git
   cd pypanther
   ```

3. **Install dependencies**:
   ```bash
   poetry install
   ```

4. **Activate the virtual environment**:
   ```bash
   poetry shell
   ```

## Testing

Run tests before submitting your changes:

```bash
poetry run pytest
```

## Style Guidelines

This project uses [Ruff](https://github.com/astral-sh/ruff) for linting and code formatting. The configuration is in `pyproject.toml`.

Run linting:

```bash
poetry run ruff check .
```

## Versioning

We use [Semantic Versioning](https://semver.org/). For example:

- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backward-compatible manner
- PATCH version for backward-compatible bug fixes

## Release Process

The maintainers will handle releases following this process:

1. Update version in pyproject.toml
2. Update CHANGELOG.md
3. Create a new release on GitHub
4. Publish to PyPI

## License

By contributing to PyPanther, you agree that your contributions will be licensed under the project's [Apache License 2.0](LICENSE.txt).
