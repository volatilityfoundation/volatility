#/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension

setup( name         = "Volatility",
       version      = "GC1",
       description  = "Volatility -- Volatile memory framwork",
       author       = "AAron Walters",
       author_email = "awalters@volatilesystems.com",  
       url          = "http://www.volatilesystems.com",
       license      = "GPL",
       packages     = ["forensics", "forensics.win32","memory_plugins","memory_objects","memory_objects.Windows","thirdparty"],
       )
