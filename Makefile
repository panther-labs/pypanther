publish:
	rm -rf dist
	git checkout main
	git pull
	poetry build
	poetry publish

test:
	poetry run pytest

fmt:
	poetry run ruff format .

lint: fmt
	poetry run ruff check .
	poetry run ruff format --check .
	poetry run mypy .
