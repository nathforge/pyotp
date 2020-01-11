SHELL=/bin/bash -e

wheel: lint clean
	./setup.py bdist_wheel

test_deps: requirements-dev.txt
	pip install -r requirements-dev.txt

lint: test_deps
	python setup.py flake8

typecheck: test_deps
	mypy --strict src

test: lint typecheck
	coverage run --branch --include 'src/*' setup.py test

init_docs: test_deps
	cd docs; sphinx-quickstart

docs: test_deps
	$(MAKE) -C docs html

install: clean
	python ./setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

.PHONY: wheel lint test test_deps docs install clean

include common.mk
