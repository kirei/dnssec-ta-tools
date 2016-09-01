# DNSSEC TA Tools

This repository contains utilities to process DNS trust anchors formatted in XML.

[![Build Status](https://api.travis-ci.org/kirei/dnssec-ta-tools.png)](https://travis-ci.org/kirei/dnssec-ta-tools)

## Example Usage

### Fetch and Verify Root Trust Anchor

    python get_trust_anchor.py

(_Compatible with both Python 2.7 and Python 3.x._)

### Standalone Trust Anchor Validator

    python3 dnssec_ta_tool.py --format dnskey --verbose
    python3 dnssec_ta_tool.py --format ds --output trust-anchor-file.conf
    python3 dnssec_ta_tool.py --format bind-managed --output managed-keys.bind
    python3 dnssec_ta_tool.py --format bind-trusted --output trusted-keys.bind

(_Compatible with Python 3.x only._)

### Convert Root TA as CSR to DNSKEY

    python3 csr2dnskey.py --csr Kjqmt7v.csr --output Kjqmt7v.csr.dnskey

(_Compatible with Python 3.x only._)

## Format Specification

- [RFC 7958](https://www.rfc-editor.org/rfc/rfc7958.txt)

## Root zone Trust Anchors

- https://www.iana.org/dnssec
- https://data.iana.org/root-anchors/root-anchors.xml

## Trust Anchor Validation

Before use, all trust anchors should be validated. Example code for how to do this using OpenSSL is available in the Makefile.
