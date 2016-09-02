SCRIPT2=	get_trust_anchor.py
SCRIPT3=	get_trust_anchor.py dnssec_ta_tool.py csr2dnskey.py

VENV2=		venv2
VENV3=		venv3

PYTHON2=	python2.7
PYTHON3=	python3.5

MODULES3=	pylint iso8601 xmltodict dnspython pycryptodomex pyOpenSSL

TMPFILES=	K*.{dnskey,ds} \
		test-anchors.{ds,dnskey} \
		root-anchors.{ds,dnskey} \
		ksk-as-{dnskey,ds}.txt root.zone \
		*.backup_*

KNOWN_DATA=	regress/known_data
KNOWN_GOOD=	regress/known_good

KEYID=		Kjqmt7v
CSR=		$(KNOWN_DATA)/$(KEYID).csr
ROOT_ANCHORS=	$(KNOWN_DATA)/root-anchors.xml
TEST_ANCHORS=	$(KNOWN_DATA)/test-anchors.xml


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

test: test2 test3

test2: $(VENV2)
	(. $(VENV2)/bin/activate; $(MAKE) regress2_offline regress2_online)

test3: $(VENV3)
	(. $(VENV3)/bin/activate; $(MAKE) regress3_offline regress3_online)

regress2_offline:
	python -m py_compile get_trust_anchor.py

regress2_online:
	python get_trust_anchor.py
	diff -u $(KNOWN_GOOD)/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u $(KNOWN_GOOD)/ksk-as-ds.txt ksk-as-ds.txt

regress3_online: regress2_online
	python -m py_compile get_trust_anchor.py

regress3_offline:
	python -m py_compile get_trust_anchor.py
	python -m py_compile dnssec_ta_tool.py
	python -m py_compile csr2dnskey.py

	python dnssec_ta_tool.py \
		--verbose \
		--format dnskey \
		--anchors $(TEST_ANCHORS) \
		--output test-anchors.dnskey
	diff -u $(KNOWN_GOOD)/test-anchors.dnskey test-anchors.dnskey

	python dnssec_ta_tool.py \
		--verbose \
		--format ds \
		--anchors $(TEST_ANCHORS) \
		--output test-anchors.ds
	diff -u $(KNOWN_GOOD)/test-anchors.ds test-anchors.ds

	python dnssec_ta_tool.py \
		--verbose \
		--format dnskey \
		--anchors $(ROOT_ANCHORS) \
		--output root-anchors.dnskey
	diff -u $(KNOWN_GOOD)/root-anchors.dnskey root-anchors.dnskey

	python dnssec_ta_tool.py \
		--verbose \
		--format ds \
		--anchors $(ROOT_ANCHORS) \
		--output root-anchors.ds
	diff -u $(KNOWN_GOOD)/root-anchors.ds root-anchors.ds

	python csr2dnskey.py \
		--csr $(CSR) \
		--output $(KEYID).dnskey
	diff -u $(KNOWN_GOOD)/$(KEYID).dnskey $(KEYID).dnskey

realclean: clean
	rm -rf $(VENV2) $(VENV3)

clean:
	rm -f $(TMPFILES)
