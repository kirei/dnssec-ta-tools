# DNSSEC TA Tools

This repository contains utilities to process DNS trust anchors formatted in XML.

## Example Usage

    python3 dnssec_ta_tool.py --format dnskey
    python3 dnssec_ta_tool.py --format ds --output trust-anchor-file.conf
    python3 dnssec_ta_tool.py --format bind-managed --output managed-keys.bind
    python3 dnssec_ta_tool.py --format bind-trusted --output trusted-keys.bind

## Format specification

- https://tools.ietf.org/html/draft-jabley-dnssec-trust-anchor

## Root zone Trust Anchors

- https://www.iana.org/dnssec
- https://data.iana.org/root-anchors/root-anchors.xml

## Trust Anchor Validation

Before use, all trust anchors should be validated. Example code for how to do this using OpenSSL is available in the Makefile.
