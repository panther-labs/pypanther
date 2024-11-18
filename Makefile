publish:
	rm -rf dist
	git checkout main
	git pull
	./pantherlogfetch.sh
	poetry build
	poetry publish

test:
	poetry run pytest

fmt:
	poetry run ruff check --select I --fix .
	poetry run ruff format .

lint: fmt
	poetry run ruff check --fix .
	poetry run ruff format --check .
	poetry run mypy .
