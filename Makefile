SCRIPT2=	get_trust_anchor.py
SCRIPT3=	get_trust_anchor.py dnssec_ta_tool.py csr2dnskey.py

VENV2=		venv2
VENV3=		venv3

PYTHON2=	python2.7
PYTHON3=	python3.5

MODULES3=	pylint iso8601 xmltodict dnspython pycryptodomex pyOpenSSL

TMPFILES=	root-anchors.xml root-anchors.p7s icannbundle.pem \
		icanncacert.pem \
		K*.{dnskey,ds} \
		test-anchors.{ds,dnskey} \
		root-anchors.{ds,dnskey} \
		ksk-as-{dnskey,ds}.txt root.zone

KNOWN_DATA=	regress/known_data
KNOWN_GOOD=	regress/known_good

KEYID=		Kjqmt7v
CSR=		$(KEYID).csr
ANCHORS=	root-anchors.xml test-anchors.xml

all:
	
lint:
	$(VENV3)/bin/pylint --reports=no $(SCRIPT3)

venv: $(VENV2) $(VENV3)

$(VENV2):
	virtualenv -p $(PYTHON2) $(VENV2)

$(VENV3):
	virtualenv -p $(PYTHON3) $(VENV3)
	$(VENV3)/bin/pip install $(MODULES3)

pip3:
	pip install $(MODULES3)

demo: $(VENV3) root-anchors.xml
	$(VENV3)/bin/python dnssec_ta_tool.py --format dnskey --verbose

test: test2 test3

test2: $(VENV2)
	$(VENV2)/bin/python get_trust_anchor.py
	diff -u $(KNOWN_GOOD)/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u $(KNOWN_GOOD)/ksk-as-ds.txt ksk-as-ds.txt

test3: $(VENV3) $(ANCHORS) $(CSR)
	$(VENV3)/bin/python dnssec_ta_tool.py --verbose \
		--anchors test-anchors.xml --format dnskey \
		--output test-anchors.dnskey
	diff -u $(KNOWN_GOOD)/test-anchors.dnskey test-anchors.dnskey

	$(VENV3)/bin/python dnssec_ta_tool.py --verbose \
		--anchors test-anchors.xml --format ds \
		--output test-anchors.ds
	diff -u $(KNOWN_GOOD)/test-anchors.ds test-anchors.ds

	$(VENV3)/bin/python dnssec_ta_tool.py --verbose \
		--anchors root-anchors.xml --format dnskey \
		--output root-anchors.dnskey
	diff -u $(KNOWN_GOOD)/root-anchors.dnskey root-anchors.dnskey

	$(VENV3)/bin/python dnssec_ta_tool.py --verbose \
		--anchors root-anchors.xml --format ds \
		--output root-anchors.ds
	diff -u $(KNOWN_GOOD)/root-anchors.ds root-anchors.ds

	$(VENV3)/bin/python csr2dnskey.py --csr $(CSR) --output $(KEYID).dnskey
	diff -u $(KNOWN_GOOD)/$(KEYID).dnskey $(KEYID).dnskey

	$(VENV3)/bin/python get_trust_anchor.py
	diff -u $(KNOWN_GOOD)/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u $(KNOWN_GOOD)/ksk-as-ds.txt ksk-as-ds.txt

travis:
	python -m py_compile get_trust_anchor.py
	python dnssec_ta_tool.py \
		--verbose \
		--format dnskey \
		--anchors test-anchors.xml \
		--output test-anchors.dnskey
	diff -u $(KNOWN_GOOD)/test-anchors.dnskey test-anchors.dnskey
	python dnssec_ta_tool.py \
		--verbose \
		--format ds \
		--anchors test-anchors.xml \
		--output test-anchors.ds
	diff -u $(KNOWN_GOOD)/test-anchors.ds test-anchors.ds
	python csr2dnskey.py \
		--csr $(KNOWN_DATA)/$(CSR) \
		--output $(KEYID).dnskey
	diff -u $(KNOWN_GOOD)/$(KEYID).dnskey $(KEYID).dnskey

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
	rm -rf $(VENV2) $(VENV3)

clean:
	rm -f $(TMPFILES)
	rm -f $(CSR)
	rm -f *.backup_*
