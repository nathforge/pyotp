#!/usr/bin/env python

from setuptools import setup

setup(
    name="pyotp",
    version="2.9.0",
    url="https://github.com/pyotp/pyotp",
    project_urls={
        "Documentation": "https://pyauth.github.io/pyotp",
        "Source Code": "https://github.com/pyauth/pyotp",
        "Issue Tracker": "https://github.com/pyauth/pyotp/issues",
        "Change Log": "https://github.com/pyauth/pyotp/blob/master/Changes.rst",
    },
    license="MIT License",
    author="PyOTP contributors",
    author_email="kislyuk@gmail.com",
    description="Python One Time Password Library",
    long_description=open("README.rst").read(),
    python_requires=">=3.7",
    install_requires=[],
    extras_require={
        "test": ["coverage", "wheel", "ruff", "mypy"],
    },
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
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    entry_points={
        'console_scripts': [
            'pyotp = pyotp.__main__:main'
        ]
    },
)
