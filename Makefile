publish:
	rm -rf dist
	git checkout main
	git pull
	poetry build
	poetry publish
