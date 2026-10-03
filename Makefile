.PHONY: up down api pipeline kafka-sink simulate dashboard terminal cli-dashboard clean

# Resolves through the normal PATH -- a hardcoded macOS Docker Desktop
# path here previously broke this Makefile on any other machine or CI
# runner whose Docker.app wasn't named "Docker 2.app".
DOCKER_CMD := docker compose
PYTHON := venv/bin/python3
UVICORN := venv/bin/uvicorn
STREAMLIT := venv/bin/streamlit

# None of the Python services read .env themselves (only docker compose
# does), so every target below loads it into the recipe's shell first --
# the same `set -a; . ./.env` scripts/start_local_demo.sh uses. Sourced by
# the shell rather than parsed with make's `include`, so values containing
# `$`, `#` or spaces behave exactly as they do there. Skipped silently when
# there's no .env yet (e.g. CI, which exports its variables directly).
LOAD_ENV := if [ -f .env ]; then set -a; . ./.env; set +a; fi;

# The stream processor's own default (/var/lib/app/faust) matches the
# container's writable mount, but isn't writable on a developer machine.
# Use a repo-local, gitignored directory unless FAUST_DATADIR is already
# set (by .env or the caller).
LOCAL_FAUST_DATADIR := $(CURDIR)/.faust-data

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
	$(LOAD_ENV) PYTHONPATH="$(CURDIR)" $(UVICORN) api.main:app --host 0.0.0.0 --port 8000

pipeline:
	@echo "[+] Starting AI Stream Processor..."
	# PYTHONPATH: ingest/stream_processor_faust.py is run as a direct
	# script path (not `python -m ...`), so Python puts inference/'s own
	# directory on sys.path instead of the repo root -- `from
	# inference.features import extract_features` then fails with
	# ModuleNotFoundError without it. Found by an automated CI job actually
	# running this exact command in a clean environment.
	$(LOAD_ENV) export REDPANDA_BROKERS=127.0.0.1:9092 FAUST_DATADIR="$${FAUST_DATADIR:-$(LOCAL_FAUST_DATADIR)}" && mkdir -p "$$FAUST_DATADIR" && PYTHONPATH="$(CURDIR)" $(PYTHON) inference/stream_processor_faust.py worker -l info

kafka-sink:
	@echo "[+] Starting Kafka-to-API Sink..."
	# Without this running, alerts flow through Kafka but are never
	# persisted -- the API and dashboards will show zero alerts
	# indefinitely with no error, since nothing else in the Quickstart
	# flow calls this script. Requires TSOC_SENSOR_TOKEN (see
	# .env.example) -- this process authenticates to the API as one
	# tenant's ingest sensor, not with TSOC_API_KEY.
	$(LOAD_ENV) PYTHONPATH="$(CURDIR)" $(PYTHON) api/kafka_sink.py

simulate:
	@echo "[+] Injecting Synthetic Attack Traffic (Burst Mode)..."
	$(LOAD_ENV) export REDPANDA_BROKERS=127.0.0.1:9092 && $(PYTHON) ingest/simulator.py --scenario mixed --burst

dashboard:
	@echo "[+] Starting SOC Dashboard..."
	$(LOAD_ENV) export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(CURDIR)" $(STREAMLIT) run dashboard/app.py

terminal:
	@echo "[+] Starting T-SOC Console..."
	$(LOAD_ENV) export REDPANDA_BROKERS=127.0.0.1:9092 && PYTHONPATH="$(CURDIR)" $(PYTHON) terminal/tsoc_console.py

cli-dashboard:
	@echo "[+] Starting T-SOC Terminal Dashboard (live feed)..."
	$(LOAD_ENV) PYTHONPATH="$(CURDIR)" $(PYTHON) dashboard/cli_dashboard.py

clean:
	@echo "[+] Cleaning up local environment..."
	rm -rf __pycache__ data/zeek_logs/*.log
	find . -type d -name "__pycache__" -exec rm -r {} +
