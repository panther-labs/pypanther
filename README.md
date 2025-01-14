# PyPanther

**pypanther** is a Python library for building Panther analysis content for the Panther cybersecurity product.
It provides a simple and intuitive interface for creating, managing, and deploying detections to enhance your security posture.
Included is a `pypanther` CLI tool to interact with your content and upload it to the Panther web app.

## Features

- **Rule Creation**: Easily create rules using Python classes and inheritance.
- **Management**: Organize and manage rules efficiently with native Python.
- **Deployment**: Upload detections and more to Panther for real-time detection.

## Installation

To install **pypanther**, use pip:

```bash
pip install pypanther
```

## Prerequisites

- Python 3.11 or higher
- [Panther](https://panther.com) account and API access

## Usage

1. **Import pypanther**: Start by importing pypanther into your Python script.
2. **Create Rules**: Subclass the `Rule` class to define new rules.
3. **Register Rules**: Register your custom rules and Panther managed rules inside your `main.py` file.
4. **Test Rules**: Test all your registered rules using `pypanther test`.
5. **Upload Rules**: Upload all registered rules with your Panther deployment using the CLI tool (`pypanther upload`).

## Getting Started

Here is a simple example to get you started:

```python
from pypanther import Rule, register, LogType, Severity


# Create a new rule
class MyRule(Rule):
    id = "MyRule"
    default_severity = Severity.HIGH
    log_types = [LogType.OKTA_SYSTEM_LOG]

    def rule(self, event):
        return event.get("status") == "breached"


# register the rule
register(MyRule)
```

Check out the [pypanther-starter-kit](https://github.com/panther-labs/pypanther-starter-kit) for more examples on how to use `pypanther`.

You can view detailed docs on the package and CLI tool on the [panther docs](https://docs.panther.com/detections/pypanther/cli).

## Local Development

We use [Poetry](https://python-poetry.org/) for dependency management and packaging. Poetry makes it easy to set up a consistent and
isolated development environment.

### Setting Up for Local Development

1. **Install Poetry**: Follow the instructions on the [Poetry website](https://python-poetry.org/docs/#installation) to install Poetry.

2. **Clone the repository**: Clone the `pypanther` repository to your local machine.

   ```bash
   git clone git@github.com:panther-labs/pypanther.git
   cd pypanther
   ```

3. **Install dependencies**: Use Poetry to install the project's dependencies.

   ```bash
   poetry install
   ```

   This will create a virtual environment and install all necessary dependencies specified in the `pyproject.toml` file.

4. **Activate the virtual environment**: You can activate the virtual environment created by Poetry using:

   ```bash
   poetry shell
   ```

5. **Testing Locally**: You can create a `main.py` file within the `pypanther` directory to test commands and functionality
   locally. This file can be used to run test commands or interact with `pypanther` features.

   - **Create a `main.py` file**: Here is an example main file. Assumes you have a folder called `custom_rules` with all your test rules.

     ```python
     # pypanther/main.py

     from pypanther import register, get_panther_rules, get_rules
     import custom_rules


     register(get_panther_rules())
     register(get_rules(custom_rules))
     ```

   - **Running the CLI**: Use the following command to run `main.py` with Poetry:

     ```bash
     poetry run python ./pypanther/main.py <cmd>
     ```

     Replace `<cmd>` with any specific commands you want to test (e.g. `test` and `upload`)

6. **Adding Dependencies**: If you need to add new dependencies, use the following command:

   ```bash
   poetry add <package-name>
   ```

   This will update the `pyproject.toml` file with the new dependency.

## Contributing

We welcome contributions! Please fork the repository and submit a pull request for review. For major changes, please open an issue first to
discuss what you would like to change.

## Issues

If you encounter any issues or have questions, please open a support ticket.

## License

**pypanther** is released under [Apache License 2.0](LICENSE.txt).
