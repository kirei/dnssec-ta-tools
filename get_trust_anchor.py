#!/usr/bin/env python

"""
DNSSEC Trust Anchor Tool
This tool writes out a copy of the current DNSSEC trust anchor.
    The primary design goal for this software is that it should be able to be run on any system
    that has just Python (either 2.7 or 3.x) and the OpenSSL command line tool.

The steps it uses are:
    Step 1. Fetch the trust anchor file from IANA using HTTPS
    Step 2. Fetch the S/MIME signature for the trust anchor file from IANA using HTTPS
    Step 3. Validate the signature on the trust anchor file using a built-in IANA CA key
    Step 4. Extract the trust anchor key digests from the trust anchor file
    Step 5. Check the validity period for each digest
    Step 6. Verify that the trust anchors match the KSK in the root zone file
    Step 7. Write out the trust anchors as a DNSKEY and DS records

Note that the validation is done against a built-in ICANN CA, not one retrieved through a
URL. This means that even if HTTPS authentication checking isn't done, the resulting
trust anchors are still cryptographically validated.
"""

from __future__ import print_function

################# Still to do:

# BIND output formats

##############################


import os, sys, datetime, base64, subprocess, codecs, xml.etree.ElementTree
import pprint, re, hashlib, struct, argparse, json


ICANN_ROOT_CA_CERT = '''
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO
TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV
BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX
DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB
MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb
cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S
G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg
ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2
paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7
MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29
iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3
DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH
6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD
2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h
15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF
0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg
j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk
-----END CERTIFICATE-----
'''

URL_ROOT_ANCHORS = "https://data.iana.org/root-anchors/root-anchors.xml"
URL_ROOT_ANCHORS_SIGNATURE = "https://data.iana.org/root-anchors/root-anchors.p7s"
URL_ROOT_ZONE = "https://www.internic.net/domain/root.zone"
URL_RESOLVER_API = "https://dns.google.com/resolve?name=.&type=dnskey"


def Die(*Strings):
    """Generic way to leave the program early"""
    sys.stderr.write("".join(Strings) + " Exiting.\n")
    exit()

# Get the urlopen function from urllib.request (Python 3) or urllib2 (Python 2)
try:
    from urllib.request import urlopen
except:
    try:
        from urllib2 import urlopen
    except:
        Die("Was not able to import urlopen from Python 2 or 3.")

# Get the StringIO function from io (Python 3) or StringIO (Python 2)
try:
    from io import StringIO
except:
    try:
        from StringIO import StringIO
    except:
        Die("Was not able to import StringIO from Python 2 or 3.")


def BytesToString(ByteArray):
    """Convert bytes that are in ASCII into strings.
    This is used for content received over URLs."""
    if isinstance(ByteArray, str):
        return str(ByteArray)
    ASCIICodec = codecs.lookup("ascii")
    return ASCIICodec.decode(ByteArray)[0]


def WriteOutFile(FileName, FileContents):
    """Write out a file that we got from a URL or string.
    Back up the file if it exists.
    There is no return value."""
    # Back up the current one if it is there
    if os.path.exists(FileName):
        try:
            os.rename(FileName, NowString+FileName)
            # It seems too wordy to say what got backed up.
            # print("Backed up {} to {}.".format(FileName, NowString+FileName))
        except:
            Die("Failed to rename {} to {}.".format(FileName, NowString+FileName))
    # Pick the mode string based on the type of contents
    if isinstance(FileContents, str):
        Mode = "wt"
    else:
        Mode = "wb"
    try:
        TrustAnchorFileObj = open(FileName, mode=Mode)
        TrustAnchorFileObj.write(FileContents)
        TrustAnchorFileObj.close()
        print("Saved file {}, length {}.".format(FileName, len(FileContents)))
    except:
        Die("Could not write out the file {}.".format(FileName))
    return


def DNSKEYtoHexOfHash(DNSKEYdict, HashType):
    """Takes a DNSKEY dict and hash type (string), and returns the hex of the hash"""
    if HashType == "1":
        ThisHash = hashlib.sha1()
    elif HashType == "2":
        ThisHash = hashlib.sha256()
    else:
        Die("A DNSKEY dict had a hash type of {}, which is unknown.".format(HashType))
    DigestContent = bytearray()
    DigestContent.append(0)  # Name of the zone, expressed in wire format
    DigestContent.extend(struct.pack("!HBB", int(DNSKEYdict["f"]),\
        int(DNSKEYdict["p"]), int(DNSKEYdict["a"])))
    DigestContent.extend(KeyBytes)
    ThisHash.update(DigestContent)
    return (ThisHash.hexdigest()).upper()


def fetch_ksk():
    """Get the KSKs, or die if they can't be found in via Google nor the zone file"""
    print("Fetching via Google...")
    ksks = fetch_ksk_from_google()
    if ksks == None:
        print("Fetching via Google failed. Fetching via the root zone file...")
        ksks = fetch_ksk_from_zonefile()
        if ksks == None:
            Die("Could not fetch the KSKs from Google nor get the root zone file.")
    if len(ksks) == 0:
        Die("No KSKs were found.")
    return ksks


def fetch_ksk_from_google():
    """Fetch root KSK via Google DNS-over-HTTPS"""
    ksks = []
    try:
        url = urlopen(URL_RESOLVER_API)
    except Exception as e:
        print("Was not able to open URL {}. The returned text was '{}'.".format(\
            URL_RESOLVER_API, e))
        return None
    try:
        data = json.loads(url.read().decode('utf-8'))
    except Exception as e:
        print("The JSON returned from Google DNS-over-HTTPS was not readable: {}".format(e))
        return None
    for answer in data['Answer']:
        if answer['type'] == 48:
            (flags, proto, alg, key_b64) = re.split("\s+", answer['data'])
            if flags == '257':
                ksks.append({'f': flags, 'p': proto, 'a': alg, 'k': key_b64})
    return ksks


def fetch_ksk_from_zonefile():
    """Fetch root KSK from the root zone file"""
    ksks = []
    try:
        url = urlopen(URL_ROOT_ZONE)
    except Exception as e:
        print("Was not able to open URL {}. The returned text was '{}'.".format(\
            URL_ROOT_ZONE, e))
        return None
    for line in url.read().decode('utf-8').split('\n'):
        if "DNSKEY\t" in line:
            (dot, TTL, IN, DNSKEY, flags, proto, alg, key_b64) = re.split(r"\s+", line)
            if flags == '257':
                ksks.append({'f': flags, 'p': proto, 'a': alg, 'k': key_b64})
    return ksks


def validate_detached_signature(ContentsFilename, SignatureFileName, CAFileName):
    """Validate a detached S/MIME signature"""
    # Make sure there is an "openssl" command in their shell path
    WhichReturn = subprocess.call("which openssl", shell=True, stdout=subprocess.PIPE)
    if WhichReturn != 0:
        Die("Could not find the 'openssl' command on this system.")
    # Run openssl to validate the signature
    ValidateCommand = "openssl smime -verify -CAfile {ca} -inform der -in {sig} -content {cont}"
    ValidatePopen = subprocess.Popen(ValidateCommand.format(\
        ca=CAFileName, sig=SignatureFileName, cont=ContentsFilename),\
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (ValidOut, ValidErr) = ValidatePopen.communicate()
    if ValidatePopen.returncode != 0:
        Die("When running openssl, the return code was {} ".format(ValidatePopen.returncode),\
            "and the output was the following.\n{}".format(ValidOut))
    else:
        print("Validation of the signature in {sig} over the file {cont} succeeded.".format(\
            sig=SignatureFileName, cont=ContentsFilename))


def extract_trust_anchors_from_xml(TrustAnchorXML):
    """Extract the trust anchor key digests from the trust anchor file"""
    # Turn the bytes from TrustAnchorXML into a string
    TrustAnchorXMLString = BytesToString(TrustAnchorXML)
    # Sanity check: make sure there is enough text in the returned stuff
    if len(TrustAnchorXMLString) < 100:
        Die("The text returned from getting {} was too short: '{}'.".format(\
            TrustAnchorURL, TrustAnchorXMLString))
    # ElementTree requries a file so use StringIO to turn the string into a file
    try:
        TrustAnchorAsFile = StringIO(TrustAnchorXMLString)  # This works for Python 3
    except:
        TrustAnchorAsFile = StringIO(unicode(TrustAnchorXMLString))  # Needed for Python 2
    # Get the tree
    TrustAnchorTree = xml.etree.ElementTree.ElementTree(file=TrustAnchorAsFile)
    # Get all the KeyDigest elements
    DigestElements = TrustAnchorTree.findall(".//KeyDigest")
    print("There were {} KeyDigest elements in the trust anchor file.".format(\
        len(DigestElements)))
    TrustAnchors = []  # Global list of dicts that is taken from the XML file
    # Collect the values for the KeyDigest subelements and attributes
    for (Count, ThisDigestElement) in enumerate(DigestElements):
        DigestValueDict = {}
        for ThisSubElement in ["KeyTag", "Algorithm", "DigestType", "Digest"]:
            try:
                ThisKeyTagText = (ThisDigestElement.find(ThisSubElement)).text
            except:
                Die("Did not find {} element in a KeyDigest in a trust anchor.".format(ThisSubElement))
            DigestValueDict[ThisSubElement] = ThisKeyTagText
        for ThisAttribute in ["validFrom", "validUntil"]:
            if ThisAttribute in ThisDigestElement.keys():
                DigestValueDict[ThisAttribute] = ThisDigestElement.attrib[ThisAttribute]
            else:
                DigestValueDict[ThisAttribute] = ""  # Note that missing attributes get empty values
        # Save this to the global TrustAnchors list
        print("Added the trust anchor {} to the list:\n{}".format(Count, pprint.pformat(\
            DigestValueDict)))
        TrustAnchors.append(DigestValueDict)
    if len(TrustAnchors) == 0:
        Die("There were no trust anchors found in the XML file.")
    return TrustAnchors


def get_valid_trust_anchors(TrustAnchors):
    ValidTrustAnchors = []  # Keep a separate list because some things are not going to go into it.
    for (Count, ThisAnchor) in enumerate(TrustAnchors):
        # Check the validity times; these only need to be accurate within a day or so
        if ThisAnchor["validFrom"] == "":
            print("Trust anchor {}: the validFrom attribute is empty,".format(Count),\
                "so not using this trust anchor.")
            continue
        DigestElementValidFrom = ThisAnchor["validFrom"]
        (FromLeft, _) = DigestElementValidFrom.split("T", 2)
        (FromYear, FromMonth, FromDay) = FromLeft.split("-")
        FromDateTime = datetime.datetime(int(FromYear), int(FromMonth), int(FromDay))
        if NowDateTime < FromDateTime:
            print("Trust anchor {}: the validFrom '{}' is later".format(Count, FromDateTime),\
                "than today, so not using this trust anchor.")
            continue
        if ThisAnchor["validUntil"] == "":
            print("Trust anchor {}: there was no validUntil attribute, ".format(Count),\
                "so the validity is OK.")
            ValidTrustAnchors.append(ThisAnchor)
        else:
            DigestElementValidUntil = ThisAnchor["validUntil"]
            (UntilLeft, _) = DigestElementValidUntil.split("T", 2)
            (UntilYear, UntilMonth, UntilDay) = UntilLeft.split("-")
            UntilDateTime = datetime.datetime(int(UntilYear), int(UntilMonth), int(UntilDay))
            if NowDateTime > UntilDateTime:
                print("Trust anchor {}: the validUntil '{}' is before ".format(Count, UntilDateTime),\
                    "today, so not using this trust anchor.")
                continue
            else:
                print("Trust anchor {}: the validity period passes.".format(Count))
                ValidTrustAnchors.append(ThisAnchor)
    if len(ValidTrustAnchors) == 0:
        Die("After checking validity dates, there were no trust anchors left.")
    print("After the date validity checks, there are now {} records.".format(len(ValidTrustAnchors)))
    return ValidTrustAnchors


CmdParse = argparse.ArgumentParser(description="DNSSEC Trust Anchor Tool")
CmdParse.add_argument("--local", dest="Local", type=str,\
    help="Name of local file to use instead of getting the trust anchor from the URL")
Opts = CmdParse.parse_args()

NowDateTime = datetime.datetime.now()
# Date string used for backup file names
NowString = "backed-up-at-" + NowDateTime.strftime("%Y-%m-%d-%H-%M-%S") + "-"

TrustAnchorFileName = "root-anchors.xml"
SignatureFileName = "root-anchors.p7s"
ICANNCAFileName = "icanncacert.pem"
DNSKEYRecordFileName = "ksk-as-dnskey.txt"
DSRecordFileName = "ksk-as-ds.txt"


### Step 1. Fetch the trust anchor file from IANA using HTTPS
if Opts.Local:
    if not os.path.exists(Opts.Local):
        Die("Could not find file {}.".format(Opts.Local))
    try:
        TrustAnchorXML = open(Opts.Local, mode="rt").read()
    except:
        Die("Could not read from file {}.".format(Opts.Local))
else:
    # Get the trust anchr file from its URL, write it to disk
    try:
        TrustAnchorURL = urlopen(URL_ROOT_ANCHORS)
    except Exception as e:
        Die("Was not able to open URL {}. The returned text was '{}'.".format(\
            URL_ROOT_ANCHORS, e))
    TrustAnchorXML = TrustAnchorURL.read()
    TrustAnchorURL.close()
WriteOutFile(TrustAnchorFileName, TrustAnchorXML)

### Step 2. Fetch the S/MIME signature for the trust anchor file from IANA using HTTPS
# Get the signature file from its URL, write it to disk
try:
    SignatureURL = urlopen(URL_ROOT_ANCHORS_SIGNATURE)
except Exception as e:
    Die("Was not able to open URL {}. returned text was '{}'.".format(\
        URL_ROOT_ANCHORS_SIGNATURE, e))
SignatureContents = SignatureURL.read()
SignatureURL.close()
WriteOutFile(SignatureFileName, SignatureContents)

### Step 3. Validate the signature on the trust anchor file using a built-in IANA CA key
# Skip this step if using a local file
if Opts.Local:
    print("Not validating the local trust anchor file.")
else:
    WriteOutFile(ICANNCAFileName, ICANN_ROOT_CA_CERT)
    validate_detached_signature(TrustAnchorFileName, SignatureFileName, ICANNCAFileName)

### Step 4. Extract the trust anchor key digests from the trust anchor file
TrustAnchors = extract_trust_anchors_from_xml(TrustAnchorXML)

### Step 5. Check the validity period for each digest
ValidTrustAnchors = get_valid_trust_anchors(TrustAnchors)

### Step 6. Verify that the trust anchors match the KSK in the root zone file
### Will be useful if we want to query the root zone instead of pulling the root zone file
# Get all DNSKEY KSKs
KSKRecords = fetch_ksk()
for key in KSKRecords:
    print("Found KSK {flags} {proto} {alg} '{keystart}...{keyend}'.".format(\
        flags=key['f'], proto=key['p'], alg=key['a'],
        keystart=key['k'][0:15], keyend=key['k'][-15:]))
# Go trough all the KSKs, decoding them and comparing them to all the trust anchors
MatchedKSKs = []
for ThisKSKRecord in KSKRecords:
    try:
        KeyBytes = base64.b64decode(ThisKSKRecord["k"])
    except:
        Die("The KSK '{}...{}' had bad Base64.".format(ThisKSKRecord[0:15], ThisKSKRecord[-15:]))
    for (Count, ThisTrustAnchor) in enumerate(ValidTrustAnchors):
        HashAsHex = DNSKEYtoHexOfHash(ThisKSKRecord, ThisTrustAnchor["DigestType"])
        if HashAsHex == ThisTrustAnchor["Digest"]:
            print("Trust anchor {} matched KSK '{}...{}'".format(Count,\
                ThisKSKRecord["k"][0:15], ThisKSKRecord["k"][-15:]))
            MatchedKSKs.append(ThisKSKRecord)
            break  # Don't check more trust anchors against this KSK
if len(MatchedKSKs) == 0:
    Die("After checking for trust anchor matches, there were no trusted KSKs.")
else:
    print("There were {} matched KSKs.".format(len(MatchedKSKs)))

### Step 7. Write out the trust anchors as a DNSKEY and DS records
for ThisMatchedKSK in MatchedKSKs:
    # Write out the DNSKEY
    DNSKEYRecordContents = ". IN DNSKEY {flags} {proto} {alg} {keyas64}".format(\
        flags=ThisMatchedKSK["f"], proto=ThisMatchedKSK["p"],\
        alg=ThisMatchedKSK["a"], keyas64=ThisMatchedKSK["k"])
    WriteOutFile(DNSKEYRecordFileName, DNSKEYRecordContents)
    # Write out the DS
    HashAsHex = DNSKEYtoHexOfHash(ThisMatchedKSK, "2")  # Always do SHA256
    # Calculate the keytag
    TagBase = bytearray()
    TagBase.extend(struct.pack("!HBB", int(ThisMatchedKSK["f"]), int(ThisMatchedKSK["p"]),\
        int(ThisMatchedKSK["a"])))
    TagBase.extend(KeyBytes)
    Accumulator = 0
    for (Counter, ThisByte) in enumerate(TagBase):
        if (Counter % 2) == 0:
            Accumulator += (ThisByte << 8)
        else:
            Accumulator += ThisByte
    ThisKeyTag = ((Accumulator & 0xFFFF) + (Accumulator>>16)) & 0xFFFF
    print("The key tag for this KSK is {}".format(ThisKeyTag))
    DSRecordContents = ". IN DS {keytag} {alg} 2 {sha256ofkey}".format(\
        keytag=ThisKeyTag, alg=ThisMatchedKSK["a"],\
        sha256ofkey=HashAsHex)
    WriteOutFile(DSRecordFileName, DSRecordContents)
