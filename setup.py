#!/usr/bin/env python

import os, sys
from distutils.core import setup, Extension


# define our OS
OS_NAME = os.uname()[0]
OS_VERS = os.uname()[2]

# First our RCTL extension
if OS_NAME == 'FreeBSD' and OS_VERS.find('9.') != -1:
  ext_rctl = Extension('pyrctl',
    define_macros = [('NEED_SOLARIS_BOOLEAN', 1)],
    include_dirs  = [
      '/usr/include', 
      '/usr/local/include'
    ],
    library_dirs  = [
      '/lib',
      '/usr/lib',
      '/usr/local/lib'
    ],
    libraries     = [
      'bsdxml',
      'geom',
      'c',
      'm',
      'nvpair',
      'sbuf',
      'umem',
      'util',
      'uutil',
      'zfs'
    ],
    sources       = ['src/pyrctl.c'])
  ext_rctl.extra_compile_args = [
    '-std=gnu89',
    '-fstack-protector',
    '-Wno-pointer-sign',
    '-Wno-unknown-pragmas'
  ]
else:
  print 'Your platform is unsupported. This module is available for FreeBSD 9.X and higher only.'
  sys.exit(-1)

if os.getenv('USER') != 'root':
  print 'You must be root to test and use this module.'
  sys.exit(-1)

setup(
  name             = 'pyrctl',
  version          = '0.8',
  description      = 'Python binding to the RCTL/RACCT set of syscalls on FreeBSD 9.X and above.',
  author           = 'Mike "Fuzzy" Partin',
  author_email     = 'mpartin@fu-manchu.org',
  url              = 'https://github.com/fuzzy/pyrctl',
  long_description = '',
  ext_modules      = [ext_rctl,]
)

