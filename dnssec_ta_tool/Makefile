VENV3=		venv3
PYTHON3=	python3.5

DISTDIRS=	*.egg-info build dist
TMPFILES=	test-anchors.{ds,dnskey} \
		root-anchors.{ds,dnskey}

KNOWN_GOOD=	../regress/known_good
KNOWN_DATA=	../regress/known_data
ROOT_ANCHORS=	$(KNOWN_DATA)/root-anchors.xml
TEST_ANCHORS=	$(KNOWN_DATA)/test-anchors.xml


all:

lint:
	$(VENV3)/bin/pylint --reports=no *.py

wheel:
	python setup.py bdist_wheel

venv: $(VENV3)

$(VENV3):
	virtualenv -p $(PYTHON3) $(VENV3)
	$(VENV3)/bin/pip install -r requirements.txt

test: $(VENV3)
	(. $(VENV3)/bin/activate; $(MAKE) regress3_offline)

regress3_offline:
	python -m py_compile dnssec_ta_tool.py

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

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ *.pyc

realclean: clean
	rm -rf $(VENV3)
