SCRIPT=		dnssec_ta_tool.py csr2dnskey.py

VENV=		venv
MODULES=	pylint iso8601 xmltodict dnspython pyOpenSSL pyCrypto

TMPFILES=	root-anchors.xml root-anchors.p7s icannbundle.pem \
		icanncacert.pem \
		K*.{dnskey,ds} \
		test-anchors.{ds,dnskey} \
		root-anchors.{ds,dnskey} \
		ksk-as-{dnskey,ds}.txt root.zone

KNOWN_GOOD=	regress/known_good

KEYID=		Kjqmt7v
CSR=		$(KEYID).csr
ANCHORS=	root-anchors.xml test-anchors.xml

all:
	
lint:
	#pep8 --max-line-length=132 $(SCRIPT)
	pylint --reports=no -d line-too-long $(SCRIPT)

$(VENV):
	virtualenv -p python3 $(VENV)
	$(VENV)/bin/pip install $(MODULES)

demo: $(VENV) root-anchors.xml
	$(VENV)/bin/python dnssec_ta_tool.py --format dnskey --verbose

test: $(VENV) $(ANCHORS) $(CSR)
	$(VENV)/bin/python dnssec_ta_tool.py --verbose \
		--anchors test-anchors.xml --format dnskey \
		--output test-anchors.dnskey
	diff -u $(KNOWN_GOOD)/test-anchors.dnskey test-anchors.dnskey

	$(VENV)/bin/python dnssec_ta_tool.py --verbose \
		--anchors test-anchors.xml --format ds \
		--output test-anchors.ds
	diff -u $(KNOWN_GOOD)/test-anchors.ds test-anchors.ds

	$(VENV)/bin/python dnssec_ta_tool.py --verbose \
		--anchors root-anchors.xml --format dnskey \
		--output root-anchors.dnskey
	diff -u $(KNOWN_GOOD)/root-anchors.dnskey root-anchors.dnskey

	$(VENV)/bin/python dnssec_ta_tool.py --verbose \
		--anchors root-anchors.xml --format ds \
		--output root-anchors.ds
	diff -u $(KNOWN_GOOD)/root-anchors.ds root-anchors.ds

	$(VENV)/bin/python csr2dnskey.py --csr $(CSR) --output $(KEYID).dnskey
	diff -u $(KNOWN_GOOD)/$(KEYID).dnskey $(KEYID).dnskey

	$(VENV)/bin/python get_trust_anchor.py
	diff -u $(KNOWN_GOOD)/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u $(KNOWN_GOOD)/ksk-as-ds.txt ksk-as-ds.txt

root-anchors.p7s:
	curl -o $@ https://data.iana.org/root-anchors/root-anchors.p7s

icannbundle.pem:
	curl -o $@ https://data.iana.org/root-anchors/icannbundle.pem

root-anchors.xml: root-anchors.p7s icannbundle.pem
	curl -o root-anchors.tmp https://data.iana.org/root-anchors/root-anchors.xml
	openssl smime -verify -inform der \
		-CAfile icannbundle.pem \
		-in root-anchors.p7s -out /dev/null \
		-content root-anchors.tmp
	mv root-anchors.tmp $@

csr: $(CSR)

$(CSR):
	curl -o $@ http://data.iana.org/root-anchors/$(KEYID).csr

realclean: clean
	rm -rf $(VENV)

clean:
	rm -f $(TMPFILES)
	rm -f $(CSR)
	rm -f backed-up-at-*
