#!/usr/bin/env python

from distutils.core import setup

setup(
    name="yenotauth",
    version="0.1",
    description="Yenot Authorization",
    author="Joel B. Mohler",
    author_email="joel@kiwistrawberry.us",
    url="https://bitbucket.org/jbmohler/yenot-auth",
    packages=["yenotauth", "yenotauth.server"],
    install_requires=["yenot", "bcrypt"],
)
