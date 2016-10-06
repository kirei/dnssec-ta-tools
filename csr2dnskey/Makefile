VENV3=		venv3
PYTHON3=	python3.5

DISTDIRS=	*.egg-info build dist
TMPFILES=	K*.{dnskey,ds}

KEYID=		Kjqmt7v


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
		--csr regress/$(KEYID).csr \
		--output $(KEYID).dnskey
	diff -u regress/$(KEYID).dnskey $(KEYID).dnskey

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ *.pyc

realclean: clean
	rm -rf $(VENV3)
