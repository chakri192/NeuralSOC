.PHONY: up down api pipeline kafka-sink simulate dashboard terminal cli-dashboard clean

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
	# api/ and dashboard/ targets below both set PYTHONPATH; this one
	# didn't, and ingest/stream_processor_faust.py is run as a direct
	# script path (not `python -m ...`), so Python puts inference/'s own
	# directory on sys.path instead of the repo root -- `from
	# inference.features import extract_features` then fails with
	# ModuleNotFoundError the moment this runs in a shell that doesn't
	# already have PYTHONPATH set some other way. Found by an automated
	# CI job actually running this exact command in a clean environment.
	export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(PWD)" $(PYTHON) inference/stream_processor_faust.py worker -l info

kafka-sink:
	@echo "[+] Starting Kafka-to-API Sink..."
	# Without this running, alerts flow through Kafka but are never
	# persisted -- the API and dashboards will show zero alerts
	# indefinitely with no error, since nothing else in the Quickstart
	# flow calls this script. Requires TSOC_SENSOR_TOKEN (see
	# .env.example) -- this process authenticates to the API as one
	# tenant's ingest sensor, not with TSOC_API_KEY.
	PYTHONPATH="$(PWD)" $(PYTHON) api/kafka_sink.py

simulate:
	@echo "[+] Injecting Synthetic Attack Traffic (Burst Mode)..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && $(PYTHON) ingest/simulator.py --scenario mixed --burst

dashboard:
	@echo "[+] Starting SOC Dashboard..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(PWD)" $(STREAMLIT) run dashboard/app.py

terminal:
	@echo "[+] Starting T-SOC Console..."
	export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(PWD)" $(PYTHON) terminal/tsoc_console.py

cli-dashboard:
	@echo "[+] Starting T-SOC Terminal Dashboard (live feed)..."
	PYTHONPATH="$(PWD)" $(PYTHON) dashboard/cli_dashboard.py

clean:
	@echo "[+] Cleaning up local environment..."
	rm -rf __pycache__ data/zeek_logs/*.log
	find . -type d -name "__pycache__" -exec rm -r {} +
