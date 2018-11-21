import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="example_pkg",
    version="0.0.1",
    author="DAVID PRYOR, NICK SIMMONS, RITU GOWLIKAR, and Cameron Willis",
    author_email="david_pryor@quadratic_insights.com",
    description="An API for connecting to an Alteryx Gallery",
    long_description="",
    long_description_content_type="text/markdown",
    url="https://github.com/daqieq/AlteryxGalleryAPI",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
