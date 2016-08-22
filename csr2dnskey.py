#!/usr/bin/env python3
#
# Copyright (c) 2016, Kirei AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""DNSSEC CSR Conversion Tool"""

import sys
import argparse
import re
import base64
import dns.dnssec
import dns.rdata
from OpenSSL.crypto import load_certificate_request, dump_publickey, FILETYPE_ASN1
from Cryptodome.PublicKey import RSA
import Cryptodome.Util.number

RR_OID = "1.3.6.1.4.1.1000.53"


def get_ds_rdata(x509name):
    """Get DS record from X509Name"""
    components = dict(x509name.get_components())
    ds_pattern = re.compile("^(.+) IN DS (.+)$")
    for attr, value in components.items():
        decoded_value = value.decode('UTF-8')
        match = ds_pattern.match(decoded_value)
        if match:
            origin_str = match.group(1)
            rdata_str = match.group(2)
            rdata = dns.rdata.from_text(rdclass=dns.rdataclass.IN,
                                        rdtype=dns.rdatatype.DS,
                                        tok=rdata_str)
            return (origin_str, rdata)


def get_algo_class_from_ds(ds_rdata):
    """Get algorithm class from DS rdata"""
    if (ds_rdata.algorithm == dns.dnssec.RSAMD5 or
            ds_rdata.algorithm == dns.dnssec.RSASHA1 or
            ds_rdata.algorithm == dns.dnssec.RSASHA1NSEC3SHA1 or
            ds_rdata.algorithm == dns.dnssec.RSASHA256 or
            ds_rdata.algorithm == dns.dnssec.RSASHA512):
        return 'RSA'
    if (ds_rdata.algorithm == dns.dnssec.DSA or
            ds_rdata.algorithm == dns.dnssec.DSANSEC3SHA1):
        return 'DSA'
    if (ds_rdata.algorithm == dns.dnssec.ECDSAP256SHA256 or
            ds_rdata.algorithm == dns.dnssec.ECDSAP384SHA384):
        return 'ECDSA'
    raise Exception('Unsupported DS algorithm family')


def ds_digest_type_as_text(digest_type):
    """Get DS digest type as mnemonic"""
    digest_types = {
        1: 'SHA1',
        2: 'SHA256'
    }
    return digest_types.get(digest_type)


def get_rsa_b64_from_der(public_key_der):
    """Get base64 encoded RSA from public key DER sequence"""
    public_key_rsa = RSA.importKey(public_key_der)
    rsa_bytes_n = Cryptodome.Util.number.long_to_bytes(public_key_rsa.n)
    rsa_bytes_e = Cryptodome.Util.number.long_to_bytes(public_key_rsa.e)
    keydata = bytearray()
    keydata.append(len(rsa_bytes_e))
    keydata.extend(rsa_bytes_e)
    keydata.extend(rsa_bytes_n)
    return base64.b64encode(keydata)


def main():
    """ Main function"""
    parser = argparse.ArgumentParser(description='DNSSEC Trust Anchor Tool')
    parser.add_argument("--verbose",
                        action='store_true',
                        help='verbose output')
    parser.add_argument("--csr",
                        metavar='filename',
                        help='CSR anchor file (root-anchors.xml)')
    parser.add_argument("--output",
                        metavar='filename',
                        help='output file (stdout)')
    args = vars(parser.parse_args())

    with open(args['csr'], "rb") as csr_fd:
        csr = csr_fd.read()

    req = load_certificate_request(FILETYPE_ASN1, csr)
    subject = req.get_subject()
    (ds_origin, ds_rdata) = get_ds_rdata(subject)
    public_key_der = dump_publickey(FILETYPE_ASN1, req.get_pubkey())

    if get_algo_class_from_ds(ds_rdata) == 'RSA':
        b64 = get_rsa_b64_from_der(public_key_der).decode('utf8')
        rdata_str = '257 3 {} {}'.format(ds_rdata.algorithm, b64)
        dnskey_rdata = dns.rdata.from_text(rdclass=dns.rdataclass.IN,
                                           rdtype=dns.rdatatype.DNSKEY,
                                           tok=rdata_str)
        dnskey_as_ds = dns.dnssec.make_ds(name=ds_origin,
                                          key=dnskey_rdata,
                                          algorithm=ds_digest_type_as_text(ds_rdata.digest_type))
    else:
        raise Exception('Unsupported public key algorithm')

    if args['output']:
        output_fd = open(args['output'], 'w')
        old_stdout = sys.stdout
        sys.stdout = output_fd

    if ds_rdata == dnskey_as_ds:
        print('{} IN DNSKEY {}'.format(ds_origin, dnskey_rdata))

    if args['output']:
        sys.stdout = old_stdout
        output_fd.close()


if __name__ == "__main__":
    main()
