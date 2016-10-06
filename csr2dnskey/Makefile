VENV3=		venv3
PYTHON3=	python3.5

DISTDIRS=	*.egg-info build dist
TMPFILES=	K*.{dnskey,ds}

KNOWN_DATA=	../regress/known_data
KNOWN_GOOD=	../regress/known_good

KEYID=		Kjqmt7v
CSR=		$(KNOWN_DATA)/$(KEYID).csr


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
	python -m py_compile csr2dnskey.py
	python csr2dnskey.py \
		--csr $(CSR) \
		--output $(KEYID).dnskey
	diff -u $(KNOWN_GOOD)/$(KEYID).dnskey $(KEYID).dnskey

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ *.pyc

realclean: clean
	rm -rf $(VENV3)
