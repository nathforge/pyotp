#!/usr/bin/env python

import os
from setuptools import setup

install_requires = [line.rstrip() for line in open(os.path.join(os.path.dirname(__file__), "requirements.txt"))]

setup(
    name="pyotp",
    version="2.3.0",
    url="https://github.com/pyotp/pyotp",
    license="MIT License",
    author="PyOTP contributors",
    author_email="kislyuk@gmail.com",
    description="Python One Time Password Library",
    long_description=open("README.rst").read(),
    install_requires=install_requires,
    packages=["pyotp"],
    package_dir={"": "src"},
    package_data={"pyotp": ["py.typed"]},
    platforms=["MacOS X", "Posix"],
    zip_safe=False,
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
