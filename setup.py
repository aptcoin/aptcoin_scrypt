from distutils.core import setup, Extension

apt_scrypt_module = Extension('apt_scrypt',
                               sources = ['scryptmodule.cpp',
                                          'scrypt.cpp'],
                               include_dirs=['.'])

setup (name = 'apt_scrypt',
       version = '1.0',
       description = 'Bindings for scrypt-nm proof of work used by Aptcoin',
       ext_modules = [apt_scrypt_module])
