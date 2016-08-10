#!/usr/bin/env python
from __future__ import print_function

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

################# Still to do:

# BIND output formats

##############################

import os, sys, datetime, base64, subprocess, codecs, xml.etree.ElementTree
import pprint, re, hashlib, struct, argparse

# Generic way to leave the program early
def Die(*Strings):
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

# Convert bytes that are in ASCII into strings.
#   This is used for content received over URLs.
def BytesToString(ByteArray):
	if type(ByteArray) == str:
		return(str(ByteArray))
	ASCIICodec = codecs.lookup("ascii")
	return(ASCIICodec.decode(ByteArray)[0])

# Write out a file that we got from a URL or string. Back up the file if it exists.
#   There is no return value.
def WriteOutFile(FileName, FileContents):
	# Back up the current one if it is there
	if os.path.exists(FileName):
		try:
			os.rename(FileName, NowString+FileName)
			# It seems too wordy to say what got backed up.
			# print("Backed up {} to {}.".format(FileName, NowString+FileName))
		except:
			Die("Failed to rename {} to {}.".format(FileName, NowString+FileName))
	# Pick the mode string based on the type of contents
	if type(FileContents) == str:
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
	return()

# Takes a DNSKEY dict and hash type (int), and returns the hex of the hash
def DNSKEYtoHexOfHash(DNSKEYdict, HashType):
	if HashType == "1":
		ThisHash = hashlib.sha1()
	elif HashType == "2":
		ThisHash = hashlib.sha256()
	else:
		Die("A DNSKEY dict had a hash type of {}, which is unknown.".format(HashType))
	DigestContent = bytearray()
	DigestContent.append(0)  # Name of the zone, expressed in wire format
	DigestContent.extend(struct.pack("!HBB", int(ThisKSKRecord["f"]),\
		int(ThisKSKRecord["p"]), int(ThisKSKRecord["a"])))
	DigestContent.extend(KeyBytes)
	ThisHash.update(DigestContent)
	return((ThisHash.hexdigest()).upper())

### Will be useful if we want to query the root zone instead of pulling the root zone file
### https://dns.google.com/resolve?name=.&type=dnskey

CmdParse = argparse.ArgumentParser(description="DNSSEC Trust Anchor Tool")
CmdParse.add_argument("--local", dest="Local", type=str,
	help="Name of local file to use instead of getting the trust anchor from the URL")
Opts = CmdParse.parse_args()

URLForRootAnchors = "https://data.iana.org/root-anchors/root-anchors.xml"
URLForRootAnchorsSignature = "https://data.iana.org/root-anchors/root-anchors.p7s"
URLForRootZone = "https://www.internic.net/domain/root.zone"

NowDateTime = datetime.datetime.now()
# Date string used for backup file names
NowString = "backed-up-at-" + NowDateTime.strftime("%Y-%m-%d-%H-%M-%S") + "-"

TrustAnchorFileName = "root-anchors.xml"
SignatureFileName = "root-anchors.p7s"
ICANNCAFileName = "icanncacert.pem"
RootZoneFileName = "root.zone"
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
		TrustAnchorURL = urlopen(URLForRootAnchors)
	except Exception as e:
		Die("Was not able to open URL {}. The returned text was '{}'.".format(\
			URLForRootAnchors, e))
	TrustAnchorXML = TrustAnchorURL.read()
	TrustAnchorURL.close()
WriteOutFile(TrustAnchorFileName, TrustAnchorXML)

### Step 2. Fetch the S/MIME signature for the trust anchor file from IANA using HTTPS
# Get the signature file from its URL, write it to disk
try:
	SignatureURL = urlopen(URLForRootAnchorsSignature)
except Exception as e:
	Die("Was not able to open URL {}. returned text was '{}'.".format(\
		URLForRootAnchorsSignature, e))
SignatureContents = SignatureURL.read()
SignatureURL.close()
WriteOutFile(SignatureFileName, SignatureContents)

### Step 3. Validate the signature on the trust anchor file using a built-in IANA CA key
# Skip this step if using a local file
if Opts.Local:
	print("Not validating the local trust anchor file.")
else:
	ICANNCACert = '''
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
	WriteOutFile(ICANNCAFileName, ICANNCACert)
	# Make sure there is an "openssl" command in their shell path
	WhichReturn = subprocess.call("which openssl", shell=True, stdout=subprocess.PIPE)
	if WhichReturn != 0:
		Die("Could not find the 'openssl' command on this system.")
	# Run openssl to validate the signature
	ValidateCommand = "openssl smime -verify -CAfile {ca} -inform der -in {sig} -content {cont}"
	ValidatePopen = subprocess.Popen(ValidateCommand.format(
		ca=ICANNCAFileName, sig=SignatureFileName, cont=TrustAnchorFileName),
		shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(ValidOut, ValidErr) = ValidatePopen.communicate()
	if ValidatePopen.returncode != 0:
		Die("When running openssl, the return code was {} ".format(ValidatePopen.returncode),\
			"and the output was the following.\n{}".format(ValidOut))
	else:
		print("Validation of the signature in {sig} over the file {cont} succeeded.".format(\
			sig=SignatureFileName, cont=TrustAnchorFileName))
	
### Step 4. Extract the trust anchor key digests from the trust anchor file
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
	for ThisSubElement in [ "KeyTag", "Algorithm", "DigestType", "Digest" ]:
		try:
			ThisKeyTagText = (ThisDigestElement.find(ThisSubElement)).text
		except:
			Die("Did not find {} element in a KeyDigest in a trust anchor.".format(ThisSubElement))
		DigestValueDict[ThisSubElement] = ThisKeyTagText
	for ThisAttribute in [ "validFrom", "validUntil" ] :
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

###	Step 5. Check the validity period for each digest
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

### Step 6. Verify that the trust anchors match the KSK in the root zone file
# Get the rootzone from its URL, write it to disk
try:
	RootZoneURL = urlopen(URLForRootZone)
except Exception as e:
	Die("Was not able to open URL {}. The returned text was '{}'.".format(RootZoneURL, e))
RootZoneContents = RootZoneURL.read()
RootZoneURL.close()
WriteOutFile(RootZoneFileName, RootZoneContents)
# There might be multiple KSKs in the root zone
KSKRecords = []
for ThisRootZoneLine in RootZoneContents.splitlines():
	ThisRootZoneLine = BytesToString(ThisRootZoneLine)
	if "DNSKEY\t257" in ThisRootZoneLine:
		(Dot, TTL, IN, DNSKEY, Flags, Proto, Alg, KeyAsBase64) = re.split("\s+", ThisRootZoneLine)
		print("Found KSK {flags} {proto} {alg} '{keystart}...{keyend}' in the root zone.".format(\
			flags=Flags, proto=Proto, alg=Alg, keystart=KeyAsBase64[0:15], keyend=KeyAsBase64[-15:]))
		KSKRecords.append({"t": TTL, "f": Flags, "p": Proto, "a": Alg, "k": KeyAsBase64})
if len(KSKRecords) == 0:
	Die("Did not find any KSKs in the root zone file.")
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
	DNSKEYRecordContents = ". {ttl} IN DNSKEY {flags} {proto} {alg} {keyas64}".format(\
		ttl=ThisMatchedKSK["t"], flags=ThisMatchedKSK["f"], proto=ThisMatchedKSK["p"],\
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
	for Counter in range(len(TagBase)):
		ThisByte = TagBase[Counter]
		if (Counter % 2) == 0:
			Accumulator += (ThisByte << 8)
		else:
			Accumulator += ThisByte
	ThisKeyTag = ((Accumulator & 0xFFFF) + (Accumulator>>16)) & 0xFFFF
	print("The key tag for this KSK is {}".format(ThisKeyTag))
	DSRecordContents = ". {ttl} IN DS {keytag} {alg} 2 {sha256ofkey}".format(\
		ttl=ThisMatchedKSK["t"], keytag=ThisKeyTag, alg=ThisMatchedKSK["a"],\
		sha256ofkey=HashAsHex)
	WriteOutFile(DSRecordFileName, DSRecordContents)
