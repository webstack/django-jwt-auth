#!/usr/bin/env python

import os
import sys
from setuptools import setup

if sys.argv[-1] == "publish":
    os.system("python setup.py sdist upload")
    os.system("python setup.py bdist_wheel upload")
    print("You probably want to also tag the version now...")
    sys.exit()


setup(
    name="webstack-django-jwt-auth",
    version="0.3.0",
    url="https://github.com/webstack/django-jwt-auth",
    license="MIT",
    description="JSON Web Token based authentication for Django",
    # Original author is "Jose Padilla <hello@jpadilla.com>"
    author="Stéphane Raimbault",
    author_email="stephane.raimbault@webstack.fr",
    packages=["jwt_auth"],
    test_suite="runtests.run_tests",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP",
    ],
    install_requires=["Django>=2.0,<3.0", "PyJWT>=1.7.1"],
)
