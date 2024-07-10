# panther-analysis-prototypes
Prototyping for large changes to panther-analysis

## Local Development
We recommend using poetry for python environment management.

To install the version of pypanther in this repository, run `poetry install` from anywhere within the repository.

pypanther commands are expected to be run from a directory containing a `main.py` file, which leaves several options
when running from this repository:
- Navigate to `pypanther/pypanther/` before running commands
- Add a `main.py` file to the root directory of this repository
- Run the `main.py` file directly with `poetry run python ./main.py`
- Test the cli with `poetry run python ./pypanther/main.py <cmd>`