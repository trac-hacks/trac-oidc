# -*- coding: utf-8 -*-

import os
from setuptools import setup

VERSION = '0.1.dev0'

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

requires = [
    'sanction',
    ]

setup(
    name='trac-auth-oauth2',
    version=VERSION,
    description='Oauth2 authentication for Trac',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Environment :: Web Environment",
        "Framework :: Trac",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python",
        "License :: OSI Approved :: BSD License",
        ],
    license='Trac license (BSD-like)',
    author='Jeff Dairiki',
    author_email='dairiki@dairiki.org',
    url='https://github.com/dairiki/trac-auth-oauth2',

    packages=['trac_auth_oauth2'],
    include_package_data=True,
    install_requires=requires,
    entry_points={
        'trac.plugins': [
            'trac_auth_oauth2 = trac_auth_oauth2',
            ],
        },
    )
