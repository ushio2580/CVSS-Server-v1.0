#!/usr/bin/env python3
"""
Setup script for CVSS v3.1 Scoring System
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cvss-scoring-system",
    version="1.0.0",
    author="CVSS Team",
    author_email="team@example.com",
    description="A web-based CVSS v3.1 scoring system with dashboard and API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cvss-server-project",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    python_requires=">=3.7",
    install_requires=[
        # No external dependencies - uses only Python standard library
    ],
    entry_points={
        "console_scripts": [
            "cvss-server=server:run_server",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
