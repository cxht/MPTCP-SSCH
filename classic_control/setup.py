from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize("/usr/local/lib/python2.7/dist-packages/gym/envs/classic_control/cdef.pyx",language="c")
)