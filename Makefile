.PHONY: up down api pipeline simulate dashboard clean

# Resolves through the normal PATH -- a hardcoded macOS Docker Desktop
# path here previously broke this Makefile on any other machine or CI
# runner whose Docker.app wasn't named "Docker 2.app".
DOCKER_CMD := docker compose
PYTHON := venv/bin/python3
UVICORN := venv/bin/uvicorn
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

api:
	@echo "[+] Starting FastAPI Backend..."
	PYTHONPATH="$(PWD)" $(UVICORN) api.main:app --host 0.0.0.0 --port 8000

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
