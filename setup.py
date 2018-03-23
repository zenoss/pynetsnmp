from setuptools import setup, find_packages

# 'make build' will build the pynetsnmp and copy them to the needed locations.

setup(
    name="pynetsnmp-2",
    version="0.1.4",
    packages=find_packages(),
    install_requires=[
        'setuptools',
        'ipaddr',
        'Twisted',
        'six',
    ],
    include_package_data=True,
    # metadata for upload to PyPI
    author="Zenoss",
    author_email="support@zenoss.com",
    maintainer='kalombo',
    maintainer_email='nogamemorebrain@gmail.com',
    description="ctypes wrapper for net-snmp.",
    long_description="This repo is a fork of https://github.com/zenoss/pynetsnmp "
                     "with opportunity to use set method.",
    license="GPLv2 or later",
    keywords=['snmp', 'twisted', 'pynetsnmp', 'netsnmp'],
    url="https://github.com/kalombos/pynetsnmp",
    download_url="https://github.com/kalombos/pynetsnmp",
    zip_safe=False
)
