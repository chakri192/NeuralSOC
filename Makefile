.PHONY: up down pipeline simulate dashboard clean

DOCKER_CMD := export PATH="/Applications/Docker 2.app/Contents/Resources/bin:$$PATH" && docker compose
PYTHON := venv/bin/python3
STREAMLIT := venv/bin/streamlit

up:
	@echo "[+] Starting Redpanda Infrastructure..."
	$(DOCKER_CMD) up -d --remove-orphans
	@echo "[+] Waiting for broker to initialize..."
	@sleep 5
	./scripts/create_topics.sh

down:
	@echo "[+] Tearing down infrastructure and volumes..."
	$(DOCKER_CMD) down -v

pipeline:
	@echo "[+] Starting AI Stream Processor..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && $(PYTHON) inference/stream_processor_faust.py worker -l info

simulate:
	@echo "[+] Injecting Synthetic Attack Traffic (Burst Mode)..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && $(PYTHON) ingest/simulator.py --scenario mixed --burst

dashboard:
	@echo "[+] Starting SOC Dashboard..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(PWD)" $(STREAMLIT) run dashboard/app.py

clean:
	@echo "[+] Cleaning up local environment..."
	rm -rf __pycache__ data/zeek_logs/*.log
	find . -type d -name "__pycache__" -exec rm -r {} +
