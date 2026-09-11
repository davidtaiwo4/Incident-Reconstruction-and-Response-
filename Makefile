.PHONY: provision build test timeline recover zeek-logs zeek-weird-check clean all

provision:
	python3 -m venv venv
	. venv/bin/activate && pip install pytest scapy oletools --break-system-packages

build:
	python3 -c "import sys; sys.path.insert(0,'timeline-builder'); import schema, classify, annotations; from parsers import sysmon, powershell, email, zeek; print('all modules import cleanly')"

test:
	. venv/bin/activate && python3 -m pytest tests/ detections/ -v

zeek-logs:
	mkdir -p working/zeek-logs
	cd working/zeek-logs && zeek -C -r $(CURDIR)/original/evidence/network/incident.pcap

zeek-weird-check:
	mkdir -p working/zeek-weird-check
	cd working/zeek-weird-check && zeek -C -r $(CURDIR)/original/evidence/network/incident.pcap
	@echo "--- weird.log check ---"
	@cat working/zeek-weird-check/weird.log 2>/dev/null || echo "no weird.log — zero anomalies flagged by Zeek's base analysis"

timeline: zeek-logs
	python3 timeline-builder/build_timeline.py

recover:
	python3 recovered/recover.py

clean:
	rm -rf working/zeek-logs working/zeek-recover working/zeek-weird-check \
	       recovered/extracted recovered/case-export.zip recovered/recovery-report.json \
	       timeline.csv conn.log http.log files.log packet_filter.log weird.log dns.log

all: provision build test timeline recover
