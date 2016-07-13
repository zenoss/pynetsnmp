# Define the image name, version and tag name for the docker build image
IMAGENAME = build-tools
VERSION = 0.0.2
TAG = zenoss/$(IMAGENAME):$(VERSION)

UID := $(shell id -u)
GID := $(shell id -g)

build-bdist:
	@echo "Building a binary distribution of pynetsnmp"
	docker run --rm \
		-v $(PWD):/mnt \
		--user $(UID):$(GID) \
		$(TAG) \
		/bin/bash -c "cd /mnt && python setup.py bdist_wheel"

build-sdist:
	@echo "Building a source distribution of pynetsnmp"
	docker run --rm \
		-v $(PWD):/mnt \
		--user $(UID):$(GID) \
		$(TAG) \
		/bin/bash -c "cd /mnt && python setup.py sdist"

# Default to building a binary distribution
build: build-bdist

clean:
	rm -rf *.pyc MANIFEST dist build pynetsnmp.egg-info
