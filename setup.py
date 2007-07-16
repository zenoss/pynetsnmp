from distutils.command.build import build as _build
from distutils.command.clean import clean as _clean
from distutils.core import setup

import os

import genconstants

VERSION='0.26.6'

class clean(_clean):
    def run(self):
        if os.path.exists('/usr/include/net-snmp/library/snmp_api.h'):
            for filename in "CONSTANTS.py", "CONSTANTS.pyc":
                if os.path.exists(filename):
                    os.remove(filename)
                _clean.run(self)

class build(_build):
    def run(self):
        if os.path.exists('/usr/include/net-snmp/library/snmp_api.h'):
            genconstants.make_imports()
            _build.run(self)

if __name__=='__main__':
    setup(name='pynetsnmp',
          version=VERSION,
          description='ctypes wrapper for net-snmp',
          author='Eric C. Newton',
          author_email='ecn@zenoss.com',
          cmdclass={'build': build, 'clean' : clean},
          package_dir = {'pynetsnmp':'.',},
          packages = ['pynetsnmp',],
          )
