#!/usr/bin/env python

from setuptools import setup

setup(
    name='dnssec_ta_tool',
    version='0.0',
    description='DNSSEC Trust Anchor Tool',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only'
    ],
    url='https://github.com/kirei/dnssec-ta-tools/dnssec_ta_tool',
    scripts=[
        'dnssec_ta_tool.py',
    ],
    install_requires=[
        'dnspython',
        'iso8601',
        'xmltodict'
    ]
)
