SCRIPT=		dnssec_ta_tool.py

VENV=		env
MODULES=	pylint iso8601 xmltodict dnspython

TMPFILES=	root-anchors.xml root-anchors.p7s icannbundle.pem


all:
	
lint:
	pep8 --max-line-length=132 $(SCRIPT)
	pylint --reports=no $(SCRIPT)

virtualenv:
	virtualenv -p python3 $(VENV)
	$(VENV)/bin/pip install 

root-anchors.p7s:
	curl -o $@ https://data.iana.org/root-anchors/root-anchors.p7s

icannbundle.pem:
	curl -o $@ http://data.iana.org/root-anchors/icannbundle.pem

root-anchors.xml: root-anchors.p7s icannbundle.pem
	curl -o root-anchors.tmp https://data.iana.org/root-anchors/root-anchors.xml
	openssl smime -verify -inform der \
		-CAfile icannbundle.pem \
		-in root-anchors.p7s -out /dev/null \
		-content root-anchors.tmp
	mv root-anchors.tmp $@

clean:
	rm -f $(TMPFILES)
