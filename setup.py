#!/usr/bin/env python
# Copyright (c) 2011-2012 CloudOps
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages
from swift_usage import __version__ as version

name = 'cs_auth'

setup(
    name=name,
    version=version,
    description='Swift middleware to authenticate against CloudStack',
    license='Apache License (2.0)',
    classifiers=['Programming Language :: Python'],
    keywords='cs_auth auth authentication openstack cloudstack',
    author='CloudOps / Will Stevens (swill)',
    author_email='wstevens@cloudops.com',
    packages=find_packages(),
    entry_points={
        'paste.filter_factory': [
            'cs_auth=cs_auth.middleware:filter_factory',
        ],
    },
)      

