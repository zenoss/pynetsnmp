from setuptools import setup, find_packages

# 'make build' will build the pynetsnmp and copy them to the needed locations.

setup(
    name = "pynetsnmp",
    version = "0.40.6-dev",
    packages=find_packages(),
    install_requires = [
        'setuptools',
    ],
    include_package_data=True,
    # metadata for upload to PyPI
    author = "Zenoss",
    author_email = "support@zenoss.com",
    description = "ctypes wrapper for net-snmp.",
    license = "GPLv2 or later",
    keywords = "zenoss pynetsnmp snmp",
    url = "http://www.zenoss.com/",
    zip_safe=False
)

