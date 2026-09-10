#!/bin/bash
# start_local_demo.sh -- brings up the whole local demo stack idempotently:
# Docker infra (Redpanda/Postgres/Redis), a working .env (generated once,
# reused after), the API, stream processor, and Kafka-to-API sink -- all as
# background processes. Deliberately does NOT start ingest/simulator.py
# (no synthetic traffic) or the dashboard/terminal console (those need a
# real foreground terminal/browser -- see the printed commands at the end).
#
# Safe to re-run: every step checks whether it's already done before
# doing it again, so running this a second time on the same machine just
# confirms everything's up rather than restarting or duplicating anything.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

_c_green='\033[0;32m'; _c_yellow='\033[0;33m'; _c_red='\033[0;31m'; _c_reset='\033[0m'
info()  { echo -e "${_c_green}[+]${_c_reset} $1"; }
warn()  { echo -e "${_c_yellow}[!]${_c_reset} $1"; }
fail()  { echo -e "${_c_red}[x]${_c_reset} $1"; exit 1; }

# --- 1. Docker Desktop -------------------------------------------------
if ! docker info >/dev/null 2>&1; then
    warn "Docker daemon not responding on the default PATH -- checking Docker Desktop's own bin dir..."
    for app_dir in "/Applications/Docker.app" "/Applications/Docker 2.app"; do
        if [ -d "$app_dir/Contents/Resources/bin" ]; then
            export PATH="$app_dir/Contents/Resources/bin:$PATH"
        fi
    done
fi

if ! docker info >/dev/null 2>&1; then
    warn "Docker still not responding -- attempting to launch Docker Desktop (up to 3 minutes)..."
    open -a "Docker" 2>/dev/null || open -a "Docker 2" 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || true
    for i in $(seq 1 18); do
        docker info >/dev/null 2>&1 && break
        sleep 10
    done
fi

docker info >/dev/null 2>&1 || fail "Docker isn't running. Start Docker Desktop manually and re-run this script."
info "Docker is up."

# --- 2. Dev TLS certs for the local Redis container ---------------------
if [ ! -f "$PROJECT_ROOT/certs/ca.crt" ]; then
    info "Generating local dev TLS certs..."
    bash scripts/generate_dev_certs.sh
else
    info "Dev certs already present."
fi

# --- 3. .env -- generate once, reuse after ------------------------------
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    info "No .env found -- generating one with fresh local-only secrets."
    cat > .env <<EOF
REDPANDA_BROKERS=localhost:9092
INTERNAL_REDPANDA_BROKERS=soc-redpanda:29092
LOG_LEVEL=INFO
MAX_EVENT_SIZE_MB=5
ENVIRONMENT=development
UI_PORT=8501
COMPOSE_POSTGRES_USER=soc_admin
COMPOSE_POSTGRES_PASSWORD=$(openssl rand -hex 16)
DATABASE_URL=sqlite:///${PROJECT_ROOT}/tsoc_local_demo.db
TSOC_API_KEY=$(openssl rand -hex 24)
TSOC_JWT_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 16)
REDIS_SSL=true
REDIS_CA_CERT_PATH=${PROJECT_ROOT}/certs/ca.crt
REDIS_CLIENT_CERT_PATH=${PROJECT_ROOT}/certs/client.crt
REDIS_CLIENT_KEY_PATH=${PROJECT_ROOT}/certs/client.key
DASHBOARD_PASSWORD=$(openssl rand -hex 8)
FAUST_DATADIR=${PROJECT_ROOT}/.faust-data
ENABLE_DOCS=true
EOF
else
    info ".env already exists -- reusing it (delete it yourself first if you want a fully fresh setup)."
fi
mkdir -p "$PROJECT_ROOT/.faust-data"
set -a; source .env; set +a

# --- 4. Infra: Redpanda + Postgres + Redis ------------------------------
info "Starting infra containers..."
docker compose up -d --remove-orphans
info "Waiting for health checks..."
for i in $(seq 1 30); do
    unhealthy=$(docker compose ps --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -v "healthy" | grep -c "Up" || true)
    [ "$unhealthy" -eq 0 ] && break
    sleep 2
done
docker compose ps --format 'table {{.Name}}\t{{.Status}}'
bash scripts/create_topics.sh >/dev/null
info "Infra healthy, topics ready."

# --- 5. API --------------------------------------------------------------
if pgrep -f "uvicorn api.main:app" >/dev/null 2>&1; then
    info "API already running."
else
    info "Starting API..."
    PYTHONPATH="$PROJECT_ROOT" nohup venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 \
        > /tmp/tsoc-demo-api.log 2>&1 &
    for i in $(seq 1 15); do
        curl -sS -m 2 http://127.0.0.1:8000/readyz >/dev/null 2>&1 && break
        sleep 1
    done
fi
curl -sS -m 5 http://127.0.0.1:8000/readyz >/dev/null 2>&1 || fail "API didn't come up -- check /tmp/tsoc-demo-api.log"
info "API is up."

# --- 6. Bootstrap the demo tenant, once ----------------------------------
if [ -z "${TSOC_SENSOR_TOKEN:-}" ]; then
    info "No TSOC_SENSOR_TOKEN yet -- bootstrapping the demo tenant..."
    BOOT_OUTPUT=$(PYTHONPATH="$PROJECT_ROOT" venv/bin/python3 scripts/bootstrap_tenant.py \
        --tenant-name "Demo Tenant" --email admin@demo.local --password "DemoDay2026!")
    echo "$BOOT_OUTPUT"
    TOKEN_LINE=$(echo "$BOOT_OUTPUT" | grep "export TSOC_SENSOR_TOKEN=")
    echo "$TOKEN_LINE" >> .env
    set -a; source .env; set +a
    info "Bootstrapped. Admin login: admin@demo.local / DemoDay2026!"
else
    info "Demo tenant already bootstrapped (TSOC_SENSOR_TOKEN already set in .env)."
fi

# --- 7. Stream processor --------------------------------------------------
if pgrep -f "inference/stream_processor_faust.py" >/dev/null 2>&1; then
    info "Stream processor already running."
else
    info "Starting stream processor..."
    PYTHONPATH="$PROJECT_ROOT" REDPANDA_BROKERS=127.0.0.1:9092 \
        nohup venv/bin/python3 inference/stream_processor_faust.py worker -l info \
        > /tmp/tsoc-demo-pipeline.log 2>&1 &
    sleep 3
fi

# --- 8. Kafka-to-API sink -------------------------------------------------
if pgrep -f "api/kafka_sink.py" >/dev/null 2>&1; then
    info "Kafka sink already running."
else
    info "Starting Kafka sink..."
    PYTHONPATH="$PROJECT_ROOT" nohup venv/bin/python3 api/kafka_sink.py \
        > /tmp/tsoc-demo-sink.log 2>&1 &
    sleep 2
fi

# --- Note: the traffic simulator is deliberately NOT started here --------
if pgrep -f "ingest/simulator.py" >/dev/null 2>&1; then
    warn "ingest/simulator.py is still running from a previous session -- traffic is live."
else
    info "No traffic simulator running -- the feed is quiet by design. See below to start one."
fi

echo
echo "======================================================================"
echo " Backend is up. Logs: /tmp/tsoc-demo-{api,pipeline,sink}.log"
echo "======================================================================"
echo
echo "Start the web dashboard (its own terminal window):"
echo "  cd $PROJECT_ROOT"
echo "  set -a; source .env; set +a"
echo "  venv/bin/streamlit run dashboard/app.py"
echo
echo "Start the terminal console (its own terminal window):"
echo "  cd $PROJECT_ROOT"
echo "  set -a; source .env; set +a"
echo "  venv/bin/python3 terminal/tsoc_console.py"
echo
echo "Start the read-only terminal dashboard, if you want it too (its own window):"
echo "  cd $PROJECT_ROOT"
echo "  set -a; source .env; set +a"
echo "  venv/bin/python3 dashboard/cli_dashboard.py    # password: \$DASHBOARD_PASSWORD in .env"
echo
echo "Log into the web dashboard / terminal console as: admin@demo.local / DemoDay2026!"
echo "(only true on a fresh bootstrap this run -- if bootstrap was skipped above, use whichever"
echo " account you already created)."
echo
echo "To resume live traffic for the demo:"
echo "  cd $PROJECT_ROOT && export REDPANDA_BROKERS=127.0.0.1:9092 && venv/bin/python3 ingest/simulator.py --scenario mixed --rate 15"
echo
echo "To stop everything:"
echo "  pkill -f 'uvicorn api.main:app'; pkill -f 'stream_processor_faust'; pkill -f 'api/kafka_sink.py'; pkill -f 'ingest/simulator.py'"
echo "  docker compose down"
