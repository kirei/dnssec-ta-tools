#!/usr/bin/env python
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


"""DNSSEC Trust Anchor Tool"""

import sys
import time
import argparse
import iso8601
import xmltodict
import dns.name
import dns.dnssec
import dns.rrset
import dns.rdata
import dns.rdataclass
import dns.resolver

DEFAULT_ANCHORS = 'root-anchors.xml'


def get_trust_anchors_as_ds(zone, digests):
    """Get currently valid Trust Anchors as DS RRset"""

    now = time.time()
    valid_ds_rdata = []

    for keydigest in digests:

        keydigest_id = keydigest['@id']
        keytag = keydigest['KeyTag']

        if '@validFrom' in keydigest:
            valid_from = iso8601.parse_date(keydigest['@validFrom']).timestamp()
            if now < valid_from:
                print('TA {} ({}) not yet valid'.format(keytag, keydigest_id),
                      file=sys.stderr)
                continue

        if '@validUntil' in keydigest:
            valid_until = iso8601.parse_date(keydigest['@validUntil']).timestamp()
            if now > valid_until:
                print('TA {} ({}) expired'.format(keytag, keydigest_id),
                      file=sys.stderr)
                continue

        print('TA {} ({}) valid'.format(keytag, keydigest_id),
              file=sys.stderr)
        valid_ds_rdata.append(ds_rdata_from_keydigest(keydigest))

    rrset = dns.rrset.from_rdata_list(dns.name.from_text(zone), 0,
                                      valid_ds_rdata)
    return rrset


def ds_rdata_from_keydigest(keydigest):
    """Return keydigest as DS rdata"""
    keytag = keydigest['KeyTag']
    algorithm = keydigest['Algorithm']
    digest_type = keydigest['DigestType']
    digest = keydigest['Digest']
    rdata_text = '{} {} {} {}'.format(keytag, algorithm, digest_type, digest)
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, rdata_text)


def ds_digest_type_as_text(digest_type):
    """Get DS digest type as mnemonic"""
    digest_types = {
        1: 'SHA1',
        2: 'SHA256'
    }
    return digest_types.get(digest_type, 'UNKNOWN')


def dnskey_from_ds_rrset(ds_rrset):
    """Match current DNSKEY RRset with DS RRset"""
    zone = ds_rrset.name
    dnskey_rrset = []

    answers = dns.resolver.query(zone, 'DNSKEY')

    for ds_rdata in ds_rrset:
        for dnskey_rdata in answers:
            if dnskey_rdata.flags & 0x0001:
                dnskey_as_ds = dns.dnssec.make_ds(zone, dnskey_rdata,
                                                  ds_digest_type_as_text(ds_rdata.digest_type))
                if dnskey_as_ds == ds_rdata:
                    print('DNSKEY {} present'.format(ds_rdata.key_tag),
                          file=sys.stderr)
                    dnskey_rrset.append(dnskey_rdata)
                else:
                    print('DNSKEY {} not present'.format(ds_rdata.key_tag),
                          file=sys.stderr)
    return dnskey_rrset


def main():
    """ Main function"""
    parser = argparse.ArgumentParser(description='DNSSEC Trust Anchor Tool')

    parser.add_argument("--anchors", metavar='anchors',
                        help='trust anchor file')
    parser.set_defaults(anchors=DEFAULT_ANCHORS)

    args = vars(parser.parse_args())

    with open(args['anchors']) as anchors_fd:
        doc = xmltodict.parse(anchors_fd.read())

    zone = doc['TrustAnchor']['Zone']
    digests = doc['TrustAnchor']['KeyDigest']

    ds_rrset = get_trust_anchors_as_ds(zone, digests)
    print('Trust Anchor DS candidates:')
    print(ds_rrset)
    print('')

    dnskey_rrset = dnskey_from_ds_rrset(ds_rrset)
    print('Trust Anchor DNSKEY candidates:')
    print(dnskey_rrset)
    print('')

if __name__ == "__main__":
    main()
