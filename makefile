IMAGENAME = zenoss/zenpackbuild
VERSION = ubuntu2204-7
TAG = $(IMAGENAME):$(VERSION)

UID := $(shell id -u)
GID := $(shell id -g)

DOCKER_COMMAND = docker run --rm -v $(PWD):/mnt -w /mnt $(TAG)

.DEFAULT_GOAL := build

.PHONY: bdist
bdist:
	$(DOCKER_COMMAND) bash -c "python setup.py bdist_wheel"

.PHONY: sdist
sdist:
	@$(DOCKER_COMMAND) bash -c "python setup.py sdist"

.PHONY: build
build: bdist

.PHONY: clean
clean:
	rm -rf *.pyc dist build pynetsnmp.egg-info

.PHONY: test
HOST ?= 127.0.0.1
test:
	docker run --rm -v $(PWD):/mnt -w /mnt --user 0 $(TAG) \
    bash -c "python setup.py bdist_wheel \
    && pip install dist/pynetsnmp*py2-none-any.whl ipaddr Twisted==20.3.0 \
    && cd test \
    && python test_runner.py --host $(HOST) \
    && chown -R $(UID):$(GID) /mnt" ;
