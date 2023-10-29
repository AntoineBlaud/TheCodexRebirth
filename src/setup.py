from setuptools import find_packages
from setuptools import setup


setup(
    name='codexrebirth',
    version='0.0.2',
    description='codexrebirth',
    author="Antoine Blaud",
    author_email="antoine.blaud@gmail.com",
    setup_requires=['setuptools'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'capstone',
        'unicorn',
        'qiling',
        'keystone-engine',
        'z3-solver',
        'superglobals',
        "easygui",
        "jsonschema",
        "openai",
        "line_profiler"
    ]
)    