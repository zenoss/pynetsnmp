# Define the image name, version and tag name for the docker build image
IMAGENAME = build-tools
VERSION = 0.0.15-dev
TAG = zenoss/$(IMAGENAME):$(VERSION)

UID := $(shell id -u)
GID := $(shell id -g)

build-bdist:
	@echo "Building a binary distribution of pynetsnmp"
	docker run --rm \
		-v $(PWD):/mnt \
		--user $(UID):$(GID) \
		$(TAG) \
		/bin/bash -c "cd /mnt && /usr/bin/python2.7 setup.py bdist_wheel"

build-sdist:
	@echo "Building a source distribution of pynetsnmp"
	docker run --rm \
		-v $(PWD):/mnt \
		--user $(UID):$(GID) \
		$(TAG) \
		/bin/bash -c "cd /mnt && /usr/local/bin/python2.7 setup.py sdist"

# Default to building a binary distribution
build: build-bdist

clean:
	rm -rf *.pyc MANIFEST dist build pynetsnmp.egg-info
