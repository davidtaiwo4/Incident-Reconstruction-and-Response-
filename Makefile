.PHONY: provision build test timeline recover clean all

provision:
	python3 -m venv venv
	. venv/bin/activate && pip install pytest scapy oletools --break-system-packages

build:
	. venv/bin/activate && python3 -c "import sys; sys.path.insert(0,'timeline-builder'); import schema, classify, annotations; from parsers import sysmon, powershell, email, zeek; print('all modules import cleanly')"

test:
	. venv/bin/activate && python3 -m pytest tests/ detections/ -v

timeline:
	. venv/bin/activate && python3 timeline-builder/build_timeline.py

recover:
	. venv/bin/activate && python3 recovered/recover.py

clean:
	rm -rf working/zeek-logs working/zeek-negative-test working/zeek-recover working/zeek-weird-check \
	       recovered/extracted recovered/case-export.zip recovered/recovery-report.json \
	       timeline-builder/timeline.csv venv __pycache__ .pytest_cache

all: provision build test timeline recover
