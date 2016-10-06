#!/usr/bin/env python

from setuptools import setup

setup(
    name='get_trust_anchor',
    version='0.0',
    description='DNSSEC Trust Anchor Tools',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only'
    ],
    url='https://github.com/kirei/dnssec-ta-tools',
    scripts=[
        'get_trust_anchor.py'
    ]
)
