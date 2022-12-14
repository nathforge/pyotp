#!/usr/bin/env python

from setuptools import setup

setup(
    name="pyotp",
    version="2.7.0",
    url="https://github.com/pyotp/pyotp",
    license="MIT License",
    author="PyOTP contributors",
    author_email="kislyuk@gmail.com",
    description="Python One Time Password Library",
    long_description=open("README.rst").read(),
    python_requires=">=3.7",
    install_requires=[],
    packages=["pyotp", "pyotp.contrib"],
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
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
