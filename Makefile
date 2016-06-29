SCRIPT=		dnssec_ta_tool.py

VENV=		env
MODULES=	pylint iso8601 xmltodict dnspython


all:
	
lint:
	pep8 --max-line-length=132 $(SCRIPT)
	pylint --reports=no $(SCRIPT)

virtualenv:
	virtualenv -p python3 $(VENV)
	$(VENV)/bin/pip install 
