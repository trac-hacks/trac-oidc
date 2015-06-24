# -*- coding: utf-8 -*-

import os
import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand

VERSION = '0.1.3'

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

requires = [
    'trac',
    'oauth2client',
    ]

tests_require = [
    'pytest',
    'pytest-capturelog',
    'Mock',
    'WebTest',
    ]


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setup(
    name='trac-oidc',
    version=VERSION,
    description='OpenID Connect authentication for Trac',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Environment :: Web Environment",
        "Framework :: Trac",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: BSD License",
        ],
    license='Trac license (BSD-like)',
    author='Jeff Dairiki',
    author_email='dairiki@dairiki.org',
    url='https://github.com/dairiki/trac-oidc',

    packages=['trac_oidc'],
    include_package_data=True,
    zip_safe=True,

    install_requires=requires,
    entry_points={
        'trac.plugins': [
            'trac_oidc = trac_oidc.trac_oidc',
            ],
        },

    tests_require=tests_require,
    cmdclass={'test': PyTest},
    extras_require={'testing': tests_require},
    )
