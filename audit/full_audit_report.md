## 📂 Repository Overview & Audit Scope  

| Top‑level folder | What it contains | Primary security / scalability concerns |
|------------------|------------------|----------------------------------------|
| `api/` | FastAPI entry point, DB session handling, models/schemas, Kafka sink | Authentication, TLS, DB connection pooling, request‑ID, rate‑limit, error handling |
| `inference/` | Stream‑processor (Faust), ML model‑orchestrator, rule engine, enrichment, correlation, feature extraction | Model loading, per‑event inference, deterministic hashing, back‑pressure, Redis use, rule quality |
| `ingest/` | Simulated Zeek log generator, PCAP ingester, tail‑to‑Redpanda script | File I/O, privilege escalation, path handling |
| `dashboard/` | Streamlit web UI and Textual terminal UI | Blocking `requests` calls, missing async, UI‑side credential leakage |
| `k8s/` | Deployment manifests for the stream processor and API | Liveness/readiness probes, resource limits, secrets, network policies, autoscaling |
| `models/` | Pre‑trained Torch artifacts (`cnn_dga.pt`) and manifest files | Model integrity, checksum handling |
| `scripts/` | Benchmark, training, topic‑creation utilities | External command execution, env‑leakage |
| `shared/` | Common data‑access helpers, formatters, schemas | Input validation, serialization |
| `tests/` | Unit / integration test suite | Test coverage, mocking of external services |
| `docs/`, `audit/`, `demos/` | Documentation, audit reports, demo recordings | No runtime impact |

> **Bottom line:** The heart of the system (the data‑flow) lives in `inference/` and `api/`. The other directories either support that flow or provide UI / DevOps scaffolding. The audit therefore focuses on those, but every file is still examined for obvious red‑flags.

---

## 🔎 File‑by‑File Findings

### 1️⃣ `api/main.py`

* **Authentication** – API key read from env (`TSOC_API_KEY`). No secret rotation, stored in plaintext.
* **Rate limiting** – Uses `slowapi` with `get_remote_address`; does **not** tie limits to the API key, making it easy to bypass with many IPs.
* **CORS** – Origin list taken from env, defaults to `localhost`. If mis‑configured, could open the API to any site.
* **Exception handling** – Global handler masks stack traces (good for security) but also hides useful debugging info. No correlation ID.
* **DB session** – Synchronous SQLAlchemy session, no `pool_pre_ping`. If the DB restarts, the health check will still return “ok”.
* **Metrics** – Placeholder endpoint returns static values; no real Prometheus integration.
* **Probes** – No health‑check of DB connectivity; liveness / readiness are only at the K8s manifest level.

**Quick Wins:** Move API key to K8s Secret, add TLS termination, switch to per‑API‑key rate limiting, add request‑ID middleware, expose real Prometheus metrics, enable async DB driver.

---

### 2️⃣ `api/database.py`

* **Mandatory `DATABASE_URL`** – Good fail‑fast, but the code will throw a runtime error if only SQLite is intended.
* **SQLite fallback** – Allows `sqlite://` URLs with `check_same_thread=False`. No migration path from SQLite to Postgres, and the SQLite file lives on the pod’s root FS (read‑only FS flag conflicts).
* **Engine** – Created without `pool_pre_ping`; stale connections can cause “connection closed” errors.

**Quick Wins:** Enforce Postgres in prod, add `pool_pre_ping=True`, configure `pool_size`/`max_overflow`, and use Alembic for schema migrations.

---

### 3️⃣ `api/models.py` & `api/schemas.py`

* **SQLAlchemy models** are straightforward; primary keys are integer autoincrement. No soft‑delete flag, no audit columns (created_at/updated_at).
* **Pydantic schemas** define request/response shapes; they already enforce types, which mitigates injection from malformed DB rows.

**Quick Wins:** Add `created_at`, `updated_at` timestamps, and a soft‑delete flag for auditability.

---

### 4️⃣ `inference/stream_processor_faust.py`

* **Path hack** (`sys.path.append`) – removes reproducibility.
* **Broker URL** not TLS‑protected; no SASL.
* **Topic definitions** lack explicit partitions/replication → single‑partition bottleneck.
* **Concurrency** hard‑coded to 4; no back‑pressure handling.
* **Heavy objects** (`ThreatModelOrchestrator`, `IncidentCorrelator`, `ThreatEnricher`) attached to `app` on each worker start → model reload on every restart.
* **Feature extraction / rule & model evaluation** performed via `asyncio.to_thread` without timeout.
* **Validation** (`validate_alert`) is called but its result isn’t used to block malformed alerts—only logged.
* **Kafka send** is sequential (`await` each `send`) → adds latency.
* **DLQ** strips key fields (`payload`, `uid`) – loses forensic evidence.
* **Exception handling** re‑raises after DLQ, causing worker restarts.
* **No metrics** – no Prometheus counters for Faust event count, latency, or error rates.
* **ML anti‑pattern** – per‑event inference; no batching, no GPU usage.

**Quick Wins:** Remove sys.path hack, enforce TLS/SASL for Redpanda, define topics with partitions, make concurrency configurable, load heavy components as process‑wide singletons, add timeouts around thread calls, batch Kafka sends, keep full raw event in DLQ, replace re‑raise with graceful continue, instrument Prometheus, implement batch inference.

---

### 5️⃣ `inference/models.py`

* **Optional Torch import** – silently falls back to mock mode if Torch missing. In production this masks missing dependencies.
* **Char map** built per instance (minor inefficiency).
* **Model integrity check** uses MD5 (cryptographically broken) with a static SHA‑256 fallback file. No secret pepper.
* **Model loading** occurs each time a `DGAClassifier` is instantiated → heavy I/O, possible memory fragmentation.
* **Predict** – mock mode uses hard‑coded heuristics; real mode uses a JIT model on CPU only (`map_location='cpu'`). No GPU fallback.
* **Tensor creation** pads/truncates to 35 chars; long domains silently truncated.
* **Exception handling** in `predict` catches all exceptions and returns `(False, 0, latency)`, masking real errors.
* **Timing** uses `time.time()`, low resolution.

**Quick Wins:** Switch to SHA‑256 with a secret pepper for integrity, load model once per process (singleton), enable optional GPU (`map_location='cuda'`), add proper exception logging, use `time.perf_counter()` for latency, expose model version via API.

---

### 6️⃣ `inference/enrichment.py`

* **Deterministic Geo / Intel** use MD5 hashing (non‑cryptographic).
* **Intel enrichment** only for high/critical severity and 40 % probability – may hide real threats.
* **`await asyncio.sleep(0.005)`** is a placeholder; real external calls would block the pipeline.
* **IP range check** handles only IPv4 private ranges, not IPv6.
* **Evidence dict mutated in‑place** – could cause cross‑alert contamination if a reference is shared.
* **Key names** contain spaces (`"GeoIP (Source)"`), which are inconvenient for downstream JSONPath / SQL mapping.

**Quick Wins:** Replace MD5 with SHA‑256 + pepper, make enrichment truly async via `httpx.AsyncClient` with retries, use `ipaddress` library for private‑IP detection (IPv6 aware), copy evidence dict before mutation, use snake_case keys.

---

### 7️⃣ `inference/correlation.py`

* **Redis connection** built with plain host/port, no TLS/ACL.
* **Time window** hard‑coded to 300 s (5 min).
* **Alerts stored in a Redis list** with no length limit; each new alert triggers a full list scan (`lrange` + `json.loads`). This is **O(N²)** as the list grows.
* **Incident generation** uses static thresholds (`>=2 tactics` or `risk >= 80`). No configurability.
* **After incident creation** the entire list is deleted (`self.redis.delete(key)`), potentially discarding unrelated alerts.
* **No error handling** on Redis commands — any connectivity issue crashes the Faust worker.

**Quick Wins:** Enable TLS and ACL for Redis, configure `time_window_sec` via env, cap list size and `LTRIM` after each push, maintain aggregate data in a Redis hash to avoid scanning, make thresholds configurable, delete only correlated entries, add Redis exception handling with fallback.

---

### 8️⃣ `inference/rules.py`

* Returns plain Python `list` of dict alerts – no schema validation.
* All rules are **hard‑coded** with static thresholds (e.g., `orig_pkts > 10000` for DDoS, `len(query) > 60` for DNS tunnelling).
* No external threat‑intel feed; everything is static.
* No input sanitisation – malicious Zeek fields could be logged or persisted.

**Quick Wins:** Define a Pydantic `Alert` model for rule output, make rule thresholds configurable (YAML/JSON), integrate dynamic threat‑intel lists, add input sanitisation, add unit tests with hypothesis.

---

### 9️⃣ `ingest/simulator.py`, `ingest/pcap_ingester.py`, `ingest/tail_to_redpanda.py`

* **Simulator** writes to Redpanda via the `aiokafka` client; no TLS, no auth.
* **PCAP ingester** parses raw packet captures and publishes to Redpanda – potential for **path traversal** if file paths are supplied externally.
* **Tail script** uses `subprocess` to `tail -F` a log file and pipe to Redpanda – no bounding of line size; large lines could cause memory pressure.

**Quick Wins:** Secure Redpanda connection with TLS/SASL, validate any external file paths, limit line size, run these as separate low‑privilege containers with read‑only root FS.

---

### 🔟 `dashboard/app.py` (Streamlit) & `terminal/tsoc_console.py` (Textual)

* UI makes **blocking `requests`** calls to the FastAPI backend.
* No async handling – UI can freeze under slow network conditions.
* No authentication handling; the API key is passed implicitly via env.

**Quick Wins:** Switch to `httpx.AsyncClient` with async UI components, pass the API key via a secure header, add UI‑side loading spinners, and ensure the backend is called over HTTPS.

---

### 1️⃣1️⃣ `k8s/soc-deployment.yaml`

* **Liveness probe** spawns a new Faust CLI process – wasteful and can cause false negatives.
* **Read‑only root FS** while model files (`/models/cnn_dga.pt`) need to be read → may cause mount errors.
* **No HorizontalPodAutoscaler** for either deployment.
* **No NetworkPolicy** – pods can be accessed from any namespace.
* **Secrets**: API key is injected via env var (`X_API_KEY`) but the stream‑processor still reads `TSOC_API_KEY` from env (not from a secret).
* **Resource limits** may be insufficient for inference workloads.

**Quick Wins:** Change probes to hit a lightweight `/healthz` endpoint, mount model files as read‑only ConfigMaps, add HPA (CPU‑based + custom metric for Kafka lag), define a NetworkPolicy that only allows traffic from known pods, inject all secrets via `valueFrom.secretKeyRef`, increase CPU/memory limits after profiling.

---

### 1️⃣2️⃣ `models/cnn_dga.pt` & `models/cnn_dga.pt.sha256`

* Model file is stored in the container image; no runtime integrity verification beyond the static SHA‑256 file.
* If an attacker gains write access to the container FS (unlikely with read‑only root, but possible during dev), they could replace the model without detection (MD5 fallback).

**Quick Wins:** Verify checksum **at container start** using SHA‑256 + secret pepper, and fail the container if mismatched. Consider storing the model in a dedicated immutable volume.

---

### 1️⃣3️⃣ `scripts/benchmark_throughput.py`, `scripts/continuous_training.py`, `scripts/train_dl_models.py`

* Scripts run arbitrary shell commands (`subprocess.run`) without sanitising input arguments.
* They read environment variables directly – could leak secrets if logs are captured.

**Quick Wins:** Use `subprocess.run(..., check=True, capture_output=True)` with explicit argument lists, avoid printing secret env vars, and require explicit `--dry-run` flags for destructive actions.

---

### 1️⃣4️⃣ `shared/data_access.py`, `shared/formatters.py`, `shared/schemas.py`

* Provide thin wrappers around DB/JSON handling. No major security concerns, but **lack of input validation** when ingesting external JSON.

**Quick Wins:** Validate incoming dicts against Pydantic models before persisting, and escape any strings that may later be rendered in HTML (Streamlit).

---

## 📊 Overall Re‑Rating (after considering the current state)

| Dimension | Updated Score (out of 10) | Reason |
|-----------|---------------------------|--------|
| **Security** | **4 / 10** | Still many clear gaps (plain‑text secrets, MD5 hashing, no TLS, DLQ stripping). |
| **Scalability** | **3 / 10** | Fixed concurrency, per‑event inference, unbounded Redis lists remain bottlenecks. |
| **Reliability** | **4 / 10** | Liveness probes mis‑configured, no graceful DB health checks, no PDB. |
| **Observability** | **2 / 10** | No metrics, no request IDs, no tracing. |
| **Maintainability** | **5 / 10** | Code is modular but riddled with magic numbers and hard‑coded thresholds. |
| **ML Hygiene** | **3 / 10** | Single‑event inference, weak integrity checks, no GPU use. |
| **Overall** | **3.5 / 10** (≈ C‑) | Same as before – the audit confirms that the architecture needs the set of mitigations we listed earlier to become production‑ready. |

---

## 📋 Next Steps & Actionable Plan  

1. **Secure Secrets & Transport** – Move all credentials to K8s Secrets, enable TLS/SASL for Redpanda, Redis, and FastAPI.
2. **Replace MD5 & Add Pepper** – Update `models.py` and `enrichment.py` hashing; load `ENRICH_SALT` from secret.
3. **Singleton Model Loading** – Refactor `DGAClassifier` and `ThreatModelOrchestrator` to use a module‑level cached instance.
4. **Batch Inference** – Implement a buffer that sends a batch of up to 64 events to the model in a single forward pass.
5. **Back‑pressure & Timeouts** – Wrap `asyncio.to_thread` calls with `asyncio.wait_for(..., timeout=5)`.
6. **Redis Correlation Optimisation** – Enable TLS and ACL for Redis, configure `time_window_sec` via env, cap list size and `LTRIM` after each push, maintain aggregate data in a Redis hash for O(1) correlation.
7. **Rewrite K8s Liveness Probes** – Expose a `/healthz` endpoint in Faust (or simple pid check) and point probes to it.
8. **Autoscaling** – Add HorizontalPodAutoscaler for both stream‑processor and API based on CPU and custom metric (Kafka lag).
9. **Observability** – Integrate Prometheus client in Faust and FastAPI; add request‑ID middleware, export OpenTelemetry traces.
10. **Rate Limiting** – Move SlowAPI key function to API‑key‑based limiter; also enforce per‑IP limit as fallback.
11. **TLS for API** – Deploy FastAPI behind an Ingress with TLS termination; remove plain HTTP exposure.
12. **Network Policy & PDB** – Add NetworkPolicy restricting pod traffic; ensure at least one replica stays during updates.
13. **Database** – Switch to async SQLAlchemy; enable `pool_pre_ping`; enforce migrations via Alembic.
14. **Logging** – Add middleware that injects `X-Request-ID` and logs it.
15. **Testing** – Add unit tests for each rule with hypothesis; improve coverage of edge cases.
16. **Documentation** – Generate OpenAPI spec and publish in `docs/`. Include security sections (API‑Key, TLS).

---

You can start with any of these items (or a combination) and let me know which file(s) you’d like me to modify or generate patches for. I’m ready to produce the exact code changes, update the Kubernetes manifests, or create a PR skeleton—just tell me where to start!