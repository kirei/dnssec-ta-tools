#!/usr/bin/env python

from setuptools import setup

setup(
    name='dnssec_ta_tools',
    version='0.0',
    description='DNSSEC Trust Anchor Tools',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only'
    ],
    url='https://github.com/kirei/dnssec-ta-tools',
    scripts=[
        'csr2dnskey.py',
        'dnssec_ta_tool.py',
        'get_trust_anchor.py'
    ],
    install_requires=[
        'setuptools',
        'iso8601',
        'xmltodict',
        'dnspython'
        'pycryptodomex',
        'pyOpenSSL'
    ]
)
