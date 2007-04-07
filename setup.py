from distutils.core import setup

import genconstants

setup(name='pynetsnmp',
      description='ctypes wrapper for net-snmp',
      author='Eric C. Newton',
      author_email='ecn@zenoss.com',
      package_dir = {'pynetsnmp':'.',},
      packages = ['pynetsnmp',],
      )
