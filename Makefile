publish:
	rm -rf dist
	git checkout main
	git pull
	poetry build
	poetry publish

test:
	poetry run pytest

fmt:
	poetry run isort .
	poetry run black .

lint: fmt
	poetry run ruff check
	poetry run isort --check .
	poetry run black --check .
	poetry run mypy .