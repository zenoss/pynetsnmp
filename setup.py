from distutils.core import setup
from version import VERSION

if __name__=='__main__':
    setup(name='pynetsnmp',
          version=VERSION,
          description='ctypes wrapper for net-snmp',
          author='Eric C. Newton',
          author_email='ecn@zenoss.com',
          package_dir = {'pynetsnmp':'.',},
          packages = ['pynetsnmp',],
          )
