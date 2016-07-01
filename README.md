# DNSSEC TA Tools

This repository contains utilities to process DNS trust anchors formatted in XML.


Format specification:

- https://tools.ietf.org/html/draft-jabley-dnssec-trust-anchor

Root zone Trust Anchors:

- https://www.iana.org/dnssec
- https://data.iana.org/root-anchors/root-anchors.xml

## TA Validation

Before use, all trust anchors should be validated. Example code for how to do this using OpenSSL is available in the Makefile.
