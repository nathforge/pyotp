#!/usr/bin/env python

import os
from setuptools import setup

install_requires = [line.rstrip() for line in open(os.path.join(os.path.dirname(__file__), "requirements.txt"))]

setup(
    name="pyotp",
    version="2.2.7",
    url="https://github.com/pyotp/pyotp",
    license="MIT License",
    author="PyOTP contributors",
    author_email="kislyuk@gmail.com",
    description="Python One Time Password Library",
    long_description=open("README.rst").read(),
    install_requires=install_requires,
    packages=["pyotp"],
    package_dir={"": "src"},
    platforms=["MacOS X", "Posix"],
    zip_safe=False,
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
