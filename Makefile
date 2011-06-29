all: build

build:
	python setup.py build

install:
	python setup.py install

dist:
	python setup.py sdist

clean:
	rm -f `find . -name "*.pyc" -o -name "*~"`
	rm -rf dist build
