#!/usr/bin/env python

from setuptools import setup

setup(
    name='csr2dnskey',
    version='0.0',
    description='Convert root DNSSEC CSR to DNSKEY',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only'
    ],
    url='https://github.com/kirei/dnssec-ta-tools/',
    scripts=[
        'csr2dnskey.py',
    ],
    install_requires=[
        'dnspython'
        'pycryptodomex',
        'pyOpenSSL'
    ]
)
