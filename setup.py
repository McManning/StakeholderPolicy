#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

#
# Copyright (C) 2015 Chase McManning <cmcmanning@gmail.com>
#
# Some code adapted from tracopt.perm.authz_policy.py 
# Copyright (C) 2007 Alec Thomas <alec@swapoff.org>
#
# Licensed under the same license as Trac
# http://trac.edgewall.org/wiki/TracLicense
#

import os
from setuptools import setup

PACKAGE = 'stakeholderpolicy'

setup(
    name = 'StakeholderPolicy',
    version = '0.1.5',
    packages = [PACKAGE],

    author = 'Chase McManning',
    author_email = 'cmcmanning@gmail.com',
    description = 'Policy to limit access to stakeholder groups within Trac',
    license = 'TODO', # Some references based on BSD 3-Clause
    zip_safe = True,

    entry_points = {
        'trac.plugins': 'StakeholderPolicy = %s' % (PACKAGE)
    }
)