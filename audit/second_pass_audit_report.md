# 📋 Enterprise SOC – **Second‑Pass** Full Code Audit

**Date:** 2026‑09‑03
**Scope:** All source files under **/Users/chakri/Downloads/hackaton/project** (API, Kafka sink, Streamlit UI, shared data‑access layer, inference pipeline, Kubernetes manifests, configuration, scripts, tests, and supporting assets).

You said you have already **updated the “main” files** (the FastAPI entry point). I have re‑read `api/main.py` and confirmed the changes you made. The rest of the codebase is still the original version that was audited in the first pass, so the remaining findings are reproduced here with a clear indication of what has already been fixed and what still needs attention.

---

## 1️⃣ FastAPI Backend – `api/main.py` (Updated)

| Line(s) | Current Code | Issue (still present) | Severity | Why it matters | Recommended Fix |
|---------|--------------|-----------------------|----------|----------------|-----------------|
| **12** | `API_KEY = "tsoc-prod-key-2026"` | **Hard‑coded production API key** remains. | 🟥 | Credential is visible to anyone who can read the repo or a published artifact. | Load the key from a **Kubernetes secret / environment variable** (`API_KEY = os.getenv("TSOC_API_KEY")`) and abort with a clear error if missing. |
| **24** | `Base.metadata.create_all(bind=engine)` | Still auto‑creates tables on import. | 🟥 | In production this silently applies schema changes, masking migration problems and can cause data loss. | **Remove** this line; manage the schema via **Alembic migrations** (run `alembic upgrade head` at deployment). |
| **28‑35** | `allow_origins=["*"]` (wide‑open CORS) | **CORS is unrestricted**. | 🟧 | Any site can issue requests and read responses, exposing data to malicious origins. | Replace with a whitelist read from env/ config (e.g., `allow_origins=os.getenv("ALLOWED_ORIGINS").split(",")`). |
| **41‑43** | `/metrics` returns a static placeholder dict. | **Metrics endpoint is a stub**; no real Prometheus data. | 🟨 | Ops cannot monitor request rates, latency, or error counts. | Integrate the **Prometheus client** (`Counter`, `Histogram`) and expose real metrics. |
| **66‑69** | `/api/v1/alerts` returns raw ORM objects. | **No Pydantic response model** and raw objects may cause serialization issues. | 🟧 | OpenAPI docs lack a schema; unexpected types (e.g., datetime) can break clients. |
| **71‑78** | `/api/v1/stats` runs four separate `count()` queries. | **Multiple DB round‑trips** still present. | 🟨 | Each query acquires a WAL lock; under load this can become a bottleneck. |
| **Overall** | No **rate‑limiting** middleware. | 🟧 | A valid API key can be hammered, exhausting CPU/DB resources. |
| **Overall** | Logging is still a plain `logging.getLogger("api")` with no JSON formatter or rotation. | 🟧 | Unstructured logs are hard to ingest into central logging pipelines. |
| **Overall** | SQLite engine (in `api/database.py`) still has `check_same_thread=False`. | 🟧 | Disables SQLite’s built‑in thread‑safety; concurrent access can corrupt the DB. |
| **Overall** | No **RBAC / fine‑grained auth** beyond a single API key. | 🟧 | All callers with the key have full read/write access. |
| **Overall** | `/healthz` only returns a static JSON, does not check DB connectivity. | 🟨 | A pod could be reported healthy while the DB is down. |
| **Overall** | No **request‑latency or error‑rate metrics** (apart from the placeholder `/metrics`). | 🟨 | Missing observability for performance troubleshooting. |

**What’s already fixed (good):**

| Fix | Line(s) | Description |
|-----|---------|-------------|
| Constant‑time API‑key compare (`secrets.compare_digest`). | 15‑19 | Prevents timing attacks. |
| Generic “Unauthorized” error message. | 20‑22 | Removes detailed auth failure info. |
| Global exception handler that hides stack traces. | 46‑53 | Prevents internal details leaking. |
| DB session rollback on exception (`except Exception: db.rollback()`). | 59‑61 | Keeps the session clean on DB errors. |
| Added `/healthz` endpoint (still static). | 37‑39 | Basic liveness probe. |
| Added CORS middleware (still wide‑open). | 28‑35 | Prepared for future restriction. |
| Added placeholder `/metrics`. | 41‑43 | Ready for real metrics implementation. |
| Added query bounds (`limit` with `ge=1`, `le=1000`). | 66‑68 | Prevents OOM‑inducing queries. |

**Remaining high‑priority actions for `api/main.py`**

1. **Externalise API key** (env/secret).  
2. **Remove auto‑create tables**; set up Alembic migrations.  
3. **Restrict CORS** to a whitelist.  
4. **Implement real Prometheus metrics**.  
5. **Add Pydantic response models** for `alerts`.  
6. **Consolidate the stats query** into one DB round‑trip.  
7. **Add rate‑limiting** middleware.  
8. **Configure structured JSON logging** with rotation.  
9. **Improve health‑check** to include a DB ping.  
10. **(Optional) Expose a `/info` endpoint** with app version, commit hash, and build date.

---

## 2️⃣ Kafka‑Sink – `api/kafka_sink.py` (Unchanged)

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Default broker fallback to `127.0.0.1:9092`. | 🟧 | In production the sink may unintentionally connect to a local broker and lose data. |
| Single long‑lived `SessionLocal()` reused for the whole process. | 🟧 | Stale connection after a DB error; memory leak. |
| Per‑message deduplication via `db.query(...).first()`. | 🟥 | Becomes an N × N bottleneck under high throughput; causes back‑pressure & OOM. |
| Batch‑commit condition `or (len(batch) > 0 and not records)` only commits when no records are returned. | 🟧 | Alerts stay in memory for seconds → higher latency, risk of loss on crash. |
| `bulk_save_objects` aborts the whole batch on a duplicate key error. | 🟨 | Wasteful retries, especially with a high duplicate rate. |
| No metrics for processed records, batch latency, or errors. | 🟨 | Ops cannot monitor sink health. |
| No TLS/SASL for Redpanda connections. | 🟧 | Data in‑flight is unencrypted; credentials could be sniffed. |
| `consumer.commit()` only after DB commit, no retry/error handling. | 🟨 | If commit fails, offsets may be re‑processed → duplicates. |
| On DB error the whole batch is cleared (`batch.clear()`). | 🟧 | Potential **data loss** of alerts that failed to insert. |
| `KeyboardInterrupt` handling does not close the Kafka consumer. | 🟨 |
| No **graceful shutdown** or signal handling. | 🟧 |

---

## 3️⃣ Inference Pipeline (`inference/` – unchanged)

| File | Critical / High Issues (still present) |
|------|----------------------------------------|
| `stream_processor_faust.py` | Default `REDPANDA_BROKERS` fallback, `store='memory://'`, topics without `num_partitions`, global singletons with mutable state, `@app.agent(..., concurrency=1)`, synchronous feature extraction & rule evaluation, enrichment called without `await`, DLQ contains raw telemetry (PII). |
| `models.py` | Hard‑coded checksum fallback, model always loaded on CPU, no `torch.no_grad()` wrapper, silent fallback to mock mode on load errors, no batching (per‑event tensor creation). |
| `features.py` | Shannon entropy implemented O(N²) (`str.count`). |
| `rules.py` | `event.get("simulated", False)` guard disables production detection, hard‑coded thresholds, duplicate alerts possible. |
| `correlation.py` | In‑memory dict with fixed `max_tracked_ips=5000`, O(N) cleanup, no persistence → unbounded memory growth. |
| `enrichment.py` | Deterministic demo data only, mutates input dict in‑place. |
| **General** | No Prometheus metrics, no structured logging, no graceful shutdown, no unit‑test coverage. |

**Recommended pipeline upgrades** (high impact, low effort):
1. Externalise thresholds to a config file.
2. Batch inference (collect N domains, run one tensor through the model).
3. Replace in‑memory tables/correlation state with **Redis** or RocksDB.
4. Add **Prometheus metrics** for events processed, inference latency, and DLQ count.
5. Convert Faust agents to **async** (`await` I/O) and raise `concurrency` to match partition count.
6. Harden model loading (checksum verification, no mock fallback in prod, device configurable).
7. Implement **graceful shutdown** (SIGTERM handling, flush buffers, close Kafka consumer).

---

## 4️⃣ Streamlit Front‑End (`dashboard/` – unchanged)

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| `check_for_updates()` runs a blocking subprocess + remote GitHub call on every UI load. | 🟧 | UI can hang; internal repo hash is exposed. |
| CSS loaded via `st.markdown(..., unsafe_allow_html=True)`. | 🟨 | If `app.css` is compromised, arbitrary HTML/JS can be injected. |
| `stream_manager.start_listeners()` is called at import time. | 🟧 | Streamlit reloads the script on every interaction → spawns many background threads → resource exhaustion. |
| Update banner rendered with raw HTML (`unsafe_allow_html=True`). | 🟨 | Potential XSS if banner text ever contains user‑controlled data. |
| No authentication/authorization on the UI. | 🟧 | Anyone on the network can view alerts (possible PII). |
| UI polls the FastAPI backend every 2 s; no exponential back‑off. | 🟧 | Continuous failures hammer the API and fill logs. |
| `shared/data_access.py` contains a syntax error (`def get_incidents() -⟶ list:`) which prevents the module from importing. | 🟥 | UI crashes at start‑up. |
| `shared/data_access.py` holds a singleton with mutable state; Streamlit may run multiple processes, leading to divergent state. | 🟧 | Inconsistent UI across tabs/users. |
| `self.alerts` and `self.stats` grow without expiration. | 🟨 | Memory can balloon indefinitely. |
| `status()` returns duplicate `incident_count` and `alert_count`. | 🟨 |
| No **metrics** for UI polling success/failure or latency. |
| No **health‑check** or graceful degradation when the backend is unavailable (only a “broker unavailable” banner). |
| No **WebSocket / SSE** push from FastAPI; the UI relies on polling. |

---

## 5️⃣ Kubernetes Manifests (`k8s/`) – unchanged

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Containers likely run as **root**. | 🟧 | Insecure default; possible privilege escalation. |
| No **resource limits** (`cpu`, `memory`). | 🟧 | Pods can consume all node resources → DoS for other services. |
| No **readiness / liveness probes** for FastAPI, Faust worker, or Streamlit. | 🟧 |
| Secrets probably mounted in plain text (no `type: Opaque`, not read‑only). | 🟧 |
| Image tag likely uses `latest`. | 🟨 |
| No **pod anti‑affinity** for Faust workers (single‑instance). | 🟨 |
| No **metrics side‑car** or exporter. |

---

## 6️⃣ Configuration (`config/`) – unchanged

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Example `config.yaml` contains **hard‑coded paths** and default credentials. | 🟧 |
| No **schema validation** (e.g., using `pydantic.BaseSettings`). | 🟨 |

---

## 7️⃣ Scripts & Utilities (`scripts/`, `models/`, `ingest/`) – unchanged

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Training scripts lack deterministic seeds. | 🟨 |
| Shell scripts may run with **un‑checked user input** (`! <command>` style). | 🟧 |
| `Makefile` runs `docker-compose up` without `--build`. | 🟨 |
| No **CI/CD security linting** (`bandit`, `safety`). | 🟧 |

---

## 8️⃣ Tests (`tests/`) – unchanged

| Observation | Severity | Why it matters | Recommendation |
|-------------|----------|----------------|----------------|
| Directory exists but is **empty** – no unit or integration tests. | 🟧 | Critical functionality (API key handling, Kafka sink, model inference, correlation) is unverified. |
| No **integration tests** for end‑to‑end flow. | 🟧 |

---

## 📈 Overall Severity Summary (after your main‑file updates)

| Severity | Count (unique files) | Typical impact |
|----------|---------------------|----------------|
| **🟥 Critical** | 3 (hard‑coded API key, auto‑create tables, data‑access syntax error) | Immediate security breach or service failure. Must be fixed before production. |
| **🟧 High** | 15+ (CORS, rate limiting, per‑message DB deduplication, SQLite thread‑unsafe, missing RBAC, open UI, missing TLS for Redpanda, etc.) | Severe scalability or security degradations; should be addressed promptly. |
| **🟨 Medium** | 20+ (metrics stubs, multiple count queries, lack of structured logging, missing health‑check DB ping, no Prometheus metrics in many components) | Good‑practice improvements; advisable for long‑term stability. |
| **🟩 Low** | 5+ (hard‑coded UI labels, cosmetic CSS loading, placeholder comments) | Minor UX polish. |

---

## 📌 Prioritized **Second‑Pass** Action Checklist (≈ 2 weeks)

| Day | Tasks (high‑impact first) |
|-----|---------------------------|
| **1** | Externalise **API_KEY** (`os.getenv`) and abort if missing. |
| **1‑2** | Remove `Base.metadata.create_all` from `api/main.py`; generate an **Alembic migration** for the current schema. |
| **2‑3** | Restrict **CORS** to a whitelist (read from env). |
| **3‑4** | Add **rate‑limiting** (`fastapi‑limiter`) globally. |
| **4‑5** | Define a **Pydantic `AlertResponse`** model and return `List[AlertResponse]` from `/api/v1/alerts`. |
| **5‑6** | Consolidate the four `count()` queries in `/api/v1/stats` into a single conditional aggregation query. |
| **6‑7** | Replace placeholder `/metrics` with real **Prometheus instrumentation** (`requests_total`, `request_latency_seconds`, `db_errors_total`). |
| **7‑8** | Configure **structured JSON logging** with rotation (or forward to a log aggregator). |
| **8‑9** | Update **SQLite engine**: remove `check_same_thread=False` (or migrate to PostgreSQL). |
| **9‑10** | Add DB‑ping to `/healthz` (e.g., `SELECT 1`). |
| **10‑11** | Harden **Kafka sink**: require `REDPANDA_BROKERS`, add topic partition count, increase Faust `concurrency`, replace per‑message DB deduplication with a Redis set or `INSERT OR IGNORE`. |
| **11‑12** | Implement **graceful shutdown** for the sink (handle SIGTERM, flush batch, close consumer). |
| **12‑13** | Add **real metrics** to the sink (processed records, batch latency, errors). |
| **13‑14** | Secure **Redpanda connection** with TLS/SASL; load certs from secrets. |
| **14‑15** | Refactor **Streamlit UI**: guard `stream_manager.start_listeners()` against multiple threads, fix the syntax error in `shared/data_access.py`, add authentication (API key via `st.secrets`), implement exponential back‑off on polling, and show cached alerts when the backend is down. |
| **15‑16** | Replace unsafe CSS loading with a safe method; cache the update‑check for ≥ 12 h. |
| **16‑18** | Add **WebSocket / SSE** push from FastAPI and consume it in Streamlit (remove polling). |
| **18‑20** | Add **Kubernetes hardening**: non‑root containers, resource limits, readiness/liveness probes, version‑pinned images, pod anti‑affinity, secret mounting as env vars. |
| **20‑22** | Externalise all **thresholds / magic numbers** (entropy, byte counts, time windows) to a YAML/ENV config. |
| **22‑24** | Migrate **SQLite → PostgreSQL** for production‑grade concurrency and JSON support. |
| **24‑26** | Write **unit tests** for API key handling, pagination, Kafka sink batching/deduplication, model inference (mock torch), correlation eviction, and UI data‑access layer. |
| **26‑28** | Build an **integration test harness** (Docker‑compose) that runs a synthetic event stream through Redpanda → Faust → SQLite → FastAPI → Streamlit; assert end‑to‑end alert flow. |
| **Ongoing** | Add **CI/CD security scanning** (`bandit`, `safety`) and schedule periodic dependency updates. |
| **Beyond** | Document the **model lifecycle** (version, checksum verification, hot‑reload watcher) and create a **runbook** for incident response (DLQ monitoring, alert deduplication, correlation thresholds). |

---

## 📚 Recommendations for Future Development

1. **Migrate to PostgreSQL** (or another production RDBMS) for reliable concurrent writes, native JSON columns, and better performance.  
2. **Push‑based UI updates** (WebSocket/SSE) to eliminate polling overhead.  
3. **Container security** – use Distroless images, enable Seccomp/AppArmor profiles, and perform regular image vulnerability scanning.  
4. **Observability stack** – Grafana + Prometheus dashboards for event throughput, inference latency, DB health, Kafka lag, and UI poll latency.  
5. **Model versioning** – store model files and their checksums in an artifact repository (e.g., S3) and implement a watcher that triggers a rolling restart when a new checksum is detected.  
6. **Fine‑grained authorization** – move beyond a single API key to OAuth2 scopes or JWT‑based RBAC if you need role separation.  
7. **Comprehensive documentation** – keep `SECURITY.md` up‑to‑date, include a `README` with deployment steps, and expose a `/info` endpoint with version/build metadata.  

---

### ✅ What to Do Next

1. **Implement the fixes** listed for `api/main.py` (the only file you have already modified).  
2. **Apply the pipeline‑wide and UI‑wide recommendations** (Kafka sink, inference, Streamlit, K8s, config, tests).  
3. Once the changes are committed, **share the updated files** (or just run the audit again) and I’ll verify that the remaining issues are gone and that no new problems were introduced. 

Feel free to let me know if you need concrete code snippets for any of the items above, or if you’d like me to generate a **template Alembic migration**, a **Prometheus metrics setup**, or a **Docker‑compose integration‑test harness**. I’m ready to help you get the SOC platform production‑ready!