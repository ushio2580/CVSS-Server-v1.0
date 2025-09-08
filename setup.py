#!/usr/bin/env python3
"""
CVSS Server v1.0 - Setup Configuration
A comprehensive web-based Common Vulnerability Scoring System (CVSS) v3.1 calculator
with advanced features including user authentication, document processing, and collaborative evaluation management.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cvss-server",
    version="1.0.0",
    author="ushio2580",
    author_email="",  # Add your email if desired
    description="A comprehensive web-based CVSS v3.1 calculator with authentication and document processing",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/ushio2580/CVSS-Server-v1.0",
    project_urls={
        "Bug Reports": "https://github.com/ushio2580/CVSS-Server-v1.0/issues",
        "Source": "https://github.com/ushio2580/CVSS-Server-v1.0",
        "Documentation": "https://github.com/ushio2580/CVSS-Server-v1.0#readme",
        "Live Demo": "https://cvss-server-v10-production.up.railway.app/",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
        "Environment :: Web Environment",
        "Framework :: Flask",  # Similar to Flask in terms of web framework
    ],
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=0.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "cvss-server=server:run_server",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "cvss",
        "vulnerability",
        "security",
        "scoring",
        "assessment",
        "web",
        "dashboard",
        "authentication",
        "document-processing",
        "collaborative",
    ],
)