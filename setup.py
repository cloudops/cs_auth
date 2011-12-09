#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='cs_auth',
    version='0.1',
    description='Swift middleware to authenticate against CloudStack',
    classifiers=['Programming Language :: Python'],
    keywords='cs_auth auth authentication openstack cloudstack',
    author='Cloudops / Will Stevens (swill)',
    author_email='wstevens@syntenic.com',
    packages=find_packages(),
    entry_points={
        'paste.filter_factory': [
            'cs_auth=cs_auth.middleware:filter_factory',
        ],
    },
)      

