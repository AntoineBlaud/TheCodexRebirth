import os

from setuptools import find_packages
from setuptools import setup
import sys




setup(
    name='codexrebirth',
    version='0.0.1',
    description='codexrebirth',
    author="Antoine Blaud",
    author_email="antoine.blaud@gmail.com",
    setup_requires=['setuptools'],
    entry_points={
    },
    packages=find_packages(),
    install_requires=[
        'capstone',
        'unicorn',
        'qiling',
        'keystone-engine',
        'z3-solver'
    ]
)    