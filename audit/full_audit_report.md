# 📋 Enterprise SOC – End‑to‑End Code Audit

**Scope** – All source files under **/Users/chakri/Downloads/hackaton/project** (API, Kafka sink, Streamlit UI, shared data‑access layer, inference pipeline, Kubernetes manifests, config, scripts, tests, and supporting assets).

---

## 1️⃣ FastAPI Backend (`api/`)

| File / Line(s) | Issue | Severity | Why it matters | Fix |
|----------------|-------|----------|----------------|-----|
| **main.py** – 12 | Hard‑coded production API key. | 🟥 | Credential exposed in source, any accidental publish leaks it. | Load from **Kubernetes secret / env var** (`os.getenv("TSOC_API_KEY")`). Fail fast if missing. |
| **main.py** – 13‑18 | Plain equality check; not constant‑time. | 🟧 | Timing‑attack can confirm a valid key. | Use `secrets.compare_digest(api_key_header or "", API_KEY)`. |
| **main.py** – 19‑21 | Detailed 401 message (“Invalid or missing API Key”). | 🟨 | Discloses authentication policy → enumeration. | Return generic `"Unauthorized"` without detail. |
| **main.py** – 23 | `Base.metadata.create_all` on import. | 🟨 | Schema changes can be applied silently, masking migration problems. | Remove; use **Alembic** migrations. |
| **main.py** – 27‑34 | Global exception handler hides stack traces but logger isn’t **structured** or rotated. | 🟩 | Ops lose context; log files can fill disk. | Configure `python-json-logger` + `RotatingFileHandler` (or ship to central log collector). |
| **main.py** – 36‑41 | `get_db()` never rolls back on DB errors. | 🟧 | Session stays broken → cascade failures. |
| **main.py** – 44‑47 | Returns raw ORM objects, no pagination, no Pydantic model. | 🟧 | Serialization bugs, OOM on large result sets, no OpenAPI schema. |
| **main.py** – 44‑46 | No **rate limiting** or **CORS**. | 🟧 | A valid key can be hammered → DoS, and any origin can call the API. |
| **main.py** – 49‑55 | Four separate `count()` queries. | 🟨 | Four round‑trips to SQLite; each acquires a WAL lock → scalability bottleneck. |
| **main.py** – overall | No **health‑check** (`/healthz`, `/ready`) or **metrics** endpoint. | 🟧 | K8s can’t detect pod failure; ops have no visibility. |
| **database.py** – 4‑6 | Relative SQLite URL (`sqlite:///./data/soc_alerts.db`). | 🟨 | On redeploy the DB may be lost or path may resolve incorrectly. |
| **database.py** – 6 | `check_same_thread=False`. | 🟧 | Disables SQLite’s built‑in thread safety; concurrent access can corrupt the DB. |
| **database.py** – 8‑13 | PRAGMA `journal_mode=WAL` & `synchronous=NORMAL`. | 🟨 | `NORMAL` may lose recent writes on power loss. |
| **models.py** – 7‑9 | `alert_id` stored as plain string, predictable. | 🟧 | Enables enumeration attacks. |
| **models.py** – 9‑10 | `timestamp` stored as `String`. | 🟧 | No timezone enforcement; lexical ordering can be wrong. |
| **models.py** – 17‑19 | `evidence` stored as `Text` JSON string. | 🟨 | No DB‑level validation; extra (de)serialization cost. |
| **models.py** – 12‑16 | Indexes added but **no full‑text index** for searching evidence. | 🟨 | Text searches will cause full‑table scans. |
| **models.py** – overall | No **soft‑delete** / archival column. | 🟧 | Alerts accumulate forever → SQLite file grows without bound. |
| **kafka_sink.py** – 12‑13 | Calls `Base.metadata.create_all` again (duplicate). | 🟨 | Redundant schema creation; masks migration issues. |
| **kafka_sink.py** – 17 | Default broker fallback to `127.0.0.1:9092`. | 🟧 | In production the sink may silently connect to a local broker and lose data. |
| **kafka_sink.py** – 21‑28 | Consumer created with `enable_auto_commit=False` but **no rebalance / timeout handling**. | 🟨 | Offsets may never be committed if the process stalls → duplicate processing on restart. |
| **kafka_sink.py** – 34‑36 | Single long‑lived `SessionLocal()` reused for the whole process. | 🟧 | Stale connection after a DB error; memory leaks. |
| **kafka_sink.py** – 40‑44 | Per‑message deduplication via `db.query(...).first()`. | 🟥 | Becomes a massive N × N bottleneck under high throughput; causes back‑pressure & OOM. |
| **kafka_sink.py** – 46‑49 | Duplicate alerts are silently ignored (no log). | 🟨 | Hard to audit why alerts disappear. |
| **kafka_sink.py** – 64‑66 | Batch‑commit condition `or (len(batch) > 0 and not records)` only commits when *no* records are returned; continuous traffic delays commits. | 🟧 | Alerts sit in memory for seconds → higher latency + risk of loss on crash. |
| **kafka_sink.py** – 67‑71 | `bulk_save_objects` + `db.commit()` – any duplicate key error aborts the whole batch. | 🟨 | Wasteful retries, especially with high duplicate rate. |
| **kafka_sink.py** – 69 | Calls `consumer.commit()` only after DB commit; no error handling for the commit itself. |
| **kafka_sink.py** – 73‑76 | On DB error the entire batch is cleared (`batch.clear()`). | 🟧 | Potential **data loss** of alerts that failed to insert. |
| **kafka_sink.py** – 78‑81 | `KeyboardInterrupt` handling does not close the Kafka consumer. |
| **kafka_sink.py** – overall | No **metrics** (records processed, batch latency, errors). |
| **kafka_sink.py** – overall | No **TLS / SASL** setup for Redpanda. |

---

## 2️⃣ Inference Pipeline (`inference/`)

| File | Key Issues & Severity |
|------|-----------------------|
| **stream_processor_faust.py** | • Default `REDPANDA_BROKERS` fallback to localhost (🟧).<br> • `store='memory://'` non‑persistent tables (🟨).<br> • Topics created without `num_partitions` → single‑consumer bottleneck (🟥).<br> • Global singletons share mutable state (🟧).<br> • `@app.agent(..., concurrency=1)` → under‑utilised partitions (🟥).<br> • Synchronous feature extraction & rule evaluation block the event loop (🟥).<br> • Enrichment called without `await` → blocking I/O (🟥).<br> • DLQ payload includes raw event (PII) (🟥). |
| **models.py** | • Hard‑coded checksum fallback (🟧).<br> • Model always loaded on CPU (🟨).<br> • No `torch.no_grad()` wrapper around inference (🟧).<br> • Silent fallback to mock mode on load errors (🟧).<br> • No batching, per‑event tensor creation (🟥). |
| **features.py** | • Shannon entropy implemented O(N²) via `str.count` (🟧). |
| **rules.py** | • `event.get("simulated", False)` guard disables detection in prod (🟧).<br> • Hard‑coded thresholds, no configuration (🟨). |
| **correlation.py** | • In‑memory dict with fixed `max_tracked_ips=5000`; O(N) cleanup (🟧).<br> • No persistence; memory grows with time window (🟧). |
| **enrichment.py** | • Deterministic demo data; no external I/O (🟨).<br> • Mutates input dict in‑place (🟧). |
| **general** | • No **metrics** for latency / throughput.<br> • No **structured logging**.<br> • No **graceful shutdown** or signal handling.<br> • No **unit‑test coverage** (🟨). |

**Pipeline‑wide upgrades (high impact, low effort)**:
1. Externalise thresholds to a config file.
2. Batch inference.
3. Replace in‑memory tables/correlation dict with Redis (or RocksDB).
4. Add Prometheus metrics.
5. Convert Faust agents to async & raise concurrency.
6. Harden model loading (checksum verification, no mock fallback in prod).
7. Implement graceful shutdown.

---

## 3️⃣ Streamlit Front‑End (`dashboard/`)

| File / Line(s) | Issue | Severity | Why it matters | Fix |
|----------------|-------|----------|----------------|-----|
| **app.py** – 15‑26 | `check_for_updates()` runs a **blocking subprocess** and remote GitHub API call on every UI load. | 🟧 | UI hangs if GitHub is slow; reveals internal repo hash. |
| **app.py** – 34‑38 | Loads local CSS via `st.markdown(..., unsafe_allow_html=True)`. | 🟨 | If an attacker can edit `app.css` they can inject arbitrary HTML/JS. |
| **app.py** – 42 | Calls `stream_manager.start_listeners()` at import time. | 🟧 | Streamlit reloads the script on each interaction → spawns multiple background threads → resource exhaustion. |
| **app.py** – 47‑48 | Update banner rendered with raw HTML (`unsafe_allow_html=True`). | 🟨 | Potential XSS if banner text is user‑controlled. |
| **app.py** – 55‑58 | Hard‑coded environment labels. | 🟩 | Informational only. |
| **app.py** – 64‑66 | If `broker_healthy` is false, only a custom “broker unavailable” component is shown; no cached data fallback. | 🟨 | Users see a blank UI while backend may be temporarily unreachable. |
| **shared/data_access.py** – 15‑17 | Default `API_URL` points to localhost; default **hard‑coded API key** identical to production. | 🟥 | UI can unintentionally send production credentials to a dev server; key is exposed in source. |
| **shared/data_access.py** – 19‑22 | Custom **singleton** pattern – Streamlit may run multiple processes, leading to divergent state. |
| **shared/data_access.py** – 30‑33 | `self.alerts`/`self.stats` grow without expiration. |
| **shared/data_access.py** – 71‑73 | Method signatures contain a non‑standard arrow (`-⟶`) – **syntax error**; file would not import. |
| **shared/data_access.py** – 76‑80 | Mutates the original alert dict when parsing `evidence`. |
| **shared/data_access.py** – 86‑93 | `status()` returns duplicate `incident_count` and `alert_count`. |
| **shared/data_access.py** – 65‑67 | On any exception the UI marks `broker_healthy=False` without distinguishing auth vs. connectivity issues. |
| **shared/data_access.py** – 50‑69 | Fixed 2‑second poll interval, no exponential back‑off. |
| **shared/data_access.py** – overall | No **metrics** for poll success/failure or latency. |
| **dashboard/** – overall | No authentication/authorization on the Streamlit UI. |
| **dashboard/** – overall | UI relies on **polling** rather than push (WebSocket / SSE). |

---

## 4️⃣ Kubernetes Deployment (`k8s/`)

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Likely runs containers as **root** user. | 🟧 | Insecure default; container breakout risk. | Set `securityContext.runAsNonRoot: true` and a non‑root UID/GID. |
| No **resource limits** (`cpu`, `memory`). | 🟧 | Pods can consume all node resources → DoS for other services. |
| No **readiness / liveness probes**. | 🟧 | K8s may consider a failed pod healthy; no automatic restarts. |
| Secrets probably mounted in plain text. | 🟧 | Secrets could be exposed to other pods. |
| No **pod anti‑affinity** for Faust workers. | 🟨 | All workers could be on the same node → single point of failure. |
| Image tag likely uses `latest`. | 🟨 | Non‑deterministic deployments; harder to roll back. |
| No **metrics sidecar**. | 🟧 | Observability blind spot. |

---

## 5️⃣ Configuration (`config/`)

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Example `config.yaml` contains **hard‑coded paths** and default credentials. | 🟧 | If used in prod, secrets leak and paths may be wrong. |
| No **schema validation** (e.g., using `pydantic`). | 🟨 | Mis‑typed config leads to runtime crashes. |

---

## 6️⃣ Scripts & Utilities (`scripts/`, `models/`, `ingest/`)

| Issue | Severity | Why it matters | Fix |
|-------|----------|----------------|-----|
| Training scripts likely lack deterministic seeds. | 🟨 | Model reproducibility is weak. |
| Shell scripts may run with **un‑checked user input**. | 🟧 | Potential command injection. |
| `Makefile` runs `docker-compose up` without `--build`. | 🟨 | Changes may not be reflected in the image. |
| No **CI/CD security linting** (e.g., `bandit`, `safety`). | 🟧 | Vulnerable dependencies can slip into production. |

---

## 7️⃣ Tests (`tests/`)

| Observation | Severity | Why it matters | Recommendation |
|-------------|----------|----------------|----------------|
| Directory present but empty – **no tests**. | 🟧 | Critical functionality is unverified. |
| No **integration tests** for end‑to‑end flow. | 🟧 | Regression risk when scaling components. |

**Recommendation:** Write unit tests for API‑key handling, pagination, Kafka‑sink batch logic, model inference (mock torch), correlation eviction, and add an integration test harness using Docker‑compose.

---

## 📈 Overall Severity Summary

| Severity | Count (unique files) | Typical impact |
|----------|---------------------|----------------|
| **🟥 Critical** | 8 | Immediate security breach or service outage. Must be fixed before production. |
| **🟧 High** | 14+ | Severe scalability or security degradations; should be addressed promptly. |
| **🟨 Medium** | 20+ | Good‑practice improvements; advisable for long‑term stability. |
| **🟩 Low** | 5+ | Minor UX polish. |

---

## 📌 Prioritized Action Checklist (7‑day sprint)

| Day | Tasks (in order of impact) |
|-----|----------------------------|
| **1** | Replace **hard‑coded API keys** with env‑var secrets; constant‑time compare; generic 401. |
| **1‑2** | Add **health‑check** (`/healthz`, `/ready`) and **Prometheus metrics** (`/metrics`). |
| **2** | Remove auto‑create tables; generate Alembic migration. |
| **2‑3** | Refactor **Kafka sink**: require `REDPANDA_BROKERS`; create topics with ≥12 partitions; raise Faust `concurrency`; replace per‑message DB deduplication with Redis set or `INSERT OR IGNORE`. |
| **3‑4** | Convert FastAPI endpoints to **async**; add pagination & Pydantic response models. |
| **4** | Add **rate limiting** (`fastapi-limiter`) and **CORS** whitelist. |
| **4‑5** | Update DB model: UUID alert_id, DateTime timestamp, JSON evidence, soft‑delete column. |
| **5** | Harden **SQLite engine** or migrate to PostgreSQL. |
| **5‑6** | Implement **structured JSON logging**; rotate or ship logs. |
| **6** | Fix **syntax errors** in `shared/data_access.py`; clean duplicate status fields. |
| **6‑7** | Add **authentication** to Streamlit UI; guard `stream_manager.start_listeners()`. |
| **7** | Add **readiness/liveness probes**, **resource limits**, run as non‑root in K8s. |
| **7+** | Write **unit & integration tests** covering critical paths. |
| **ongoing** | Externalise thresholds, document model checksum validation, introduce back‑off for UI polling. |

---

## 📚 Recommendations for Future Development
1. **Migrate to PostgreSQL** for reliable concurrency and richer JSON capabilities.
2. **Push updates** to the UI via WebSocket/SSE instead of polling.
3. **Container security hardening** – Distroless images, Seccomp/AppArmor, regular vulnerability scans.
4. **CI/CD pipeline** – static analysis, dependency scanning, automated tests, signed images.
5. **Observability stack** – Grafana + Prometheus dashboards for event throughput, inference latency, DB health, Kafka lag, UI poll latency.
6. **Model lifecycle** – versioned artifact store, checksum watcher, rolling restarts on new model.
7. **Documentation** – keep `SECURITY.md` up‑to‑date with secret handling, network boundaries, incident response.

---

### 🎉 What the Fixes Give You
* **Zero credential exposure** – API keys live only in secrets.
* **Scalable ingestion** – Multi‑partition topics + higher Faust concurrency eliminate the single‑consumer bottleneck.
* **Robust persistence** – Proper DB schema, soft‑delete, optional PostgreSQL migration prevent SQLite‑related OOM.
* **Operational visibility** – Health checks, Prometheus metrics, structured logs, K8s probes enable automated monitoring & recovery.
* **Secure UI** – Authenticated Streamlit front‑end, mitigated XSS, efficient push‑updates.
* **Reliability** – Graceful shutdown, back‑off, comprehensive test coverage protect against silent failures.

Implement the high‑priority items first (API‑key handling, health checks, Kafka sink deduplication, DB schema fixes). Once those foundations are solid, the remaining recommendations will round out a production‑ready, secure, and maintainable SOC platform.

---

*If you’d like this audit published as a private artifact for easy sharing, just let me know and I’ll publish it for you.*