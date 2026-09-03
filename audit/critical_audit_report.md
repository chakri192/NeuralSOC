# 🔎 Ruthless SOC‑Platform Audit
**Scope:** Ingestion → Faust → ML → Enrichment → Correlation → FastAPI → Persistence → Kubernetes  

Below you’ll find a **line‑by‑line** security / scalability / reliability review of the high‑impact source files you asked for, followed by **consolidated recommendations** and a ready‑to‑use **task list**.

---

## 1️⃣ `inference/stream_processor_faust.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 12‑13 | **`sys.path.append` hack** – mutates `PYTHONPATH` at runtime. | Makes import order unpredictable; can inadvertently import a malicious module placed on the filesystem. | Remove the hack. Install the package via `pip install -e .` or set `PYTHONPATH` outside the process. |
| 21‑22 | **Hard‑coded broker string** (`'kafka://{BROKERS}'`). No TLS / SASL. | Anyone who can reach the network can produce/consume topics → data exfiltration, injection. | Use `kafka://user:pass@host:port` with TLS (`security_protocol=SASL_SSL`). Pull credentials from a secret (`REDPANDA_USER`, `REDPANDA_PASSWORD`). |
| 48‑52 | **Topic creation without explicit partitions / replication**. | Default single‑partition ⇒ a single worker becomes a bottleneck; no redundancy → data loss on node failure. | Define `app.topic('raw_traffic', partitions=12, replication=2)` (tune based on throughput). |
| 56‑60 | **Graceful‑shutdown only logs**; does not flush pending messages. | In‑flight alerts may be lost when the pod receives SIGTERM. | Call `await app.flows.stop()` or `await app.wait_until_stopped()` before `await app.stop()`. |
| 64‑68 | **Heavy objects attached to `app` on every worker start**. If a worker crashes and restarts, the model is re‑loaded repeatedly. | Excessive CPU / memory churn, possible model‑hash mismatch. | Use a **process‑wide singleton** (`@lru_cache` or module‑level global) and load once per pod, not per worker. |
| 70‑86 | `format_alert` builds a dict from raw Zeek fields without sanitisation. | Malicious Zeek logs could inject unexpected keys (`__class__`, `$ref`, etc.) that later get persisted to SQLite / Elasticsearch. | Whitelist allowed keys, coerce values to primitive types, and run through `pydantic` validation (`schemas.Alert`). |
| 92‑124 | **Agent definition – `concurrency=4` is static**. | Fixed worker count may under‑utilise CPU on larger nodes or overwhelm small nodes. No back‑pressure handling. | Make `concurrency` configurable via env (`FAUST_CONCURRENCY`) and set `max_poll_records` to match downstream capacity. |
| 95‑102 | **`asyncio.to_thread` for feature extraction & rule/model evaluation** – no timeout. | A badly‑behaving rule (e.g. infinite loop) can block the worker forever. |
| 106‑112 | **`validate_alert` result ignored** beyond logging; invalid alerts are dropped silently. | Potential loss of important telemetry; also, the DLQ may flood if many malformed alerts appear. |
| 114‑119 | **Sequential `await security_alerts_topic.send` and `await incidents_topic.send`**. | Each `await` incurs a round‑trip to Redpanda → latency add‑up (≈ 2 ms per send). |
| 122‑129 | **DLQ handling: strips many fields (`id.orig_h`, `payload`, etc.)**. | May discard forensic evidence needed for incident response. |
| 125‑129 | **Re‑raising the exception after DLQ**. The worker crashes, causing a restart loop. |
| 131‑132 | **`if __name__ == '__main__': app.main()`** – will start Faust **and the CLI** in the same process when the module is imported (e.g. by tests). |
| **Overall pattern** | **No monitoring / metrics** (no Prometheus counters, no logging of processing latency). |
| **ML anti‑pattern** | Model inference (`app.orchestrator.evaluate`) runs **per‑event** in a thread pool, not batched. |

---

## 2️⃣ `inference/models.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 7‑11 | **Optional import of `torch`** with `TORCH_AVAILABLE`. If `torch` is unavailable, the whole orchestrator silently falls back to mock mode. |
| 24‑26 | **`self.char_map` built per‑instance**. |
| 28‑34 | **Model integrity verification** uses `hashlib.md5(..., usedforsecurity=False)`. MD5 is **cryptographically broken**. |
| 35‑48 | **Model loading occurs on every `DGAClassifier` init**. |
| 55‑66 | **`predict`**: uses a **hard‑coded entropy/length heuristic** for mock mode and returns a tuple `(bool, score, latency)`. |
| 58‑66 | **`if len(encoded) < 35:` padding with zeros** – no explicit bounds check on input length; large domains get truncated silently. |
| 73‑80 | **`torch.no_grad()` block** – good, but the surrounding `try/except` catches *all* exceptions and returns a generic failure. |
| 83‑88 | **Latency measured with `time.time()`** – insufficient resolution on high‑throughput systems. |
| 91‑122 | **`ThreatModelOrchestrator`**: constructs a `DGAClassifier` per instance; no cleanup. |
| 95‑122 | **`evaluate`** filters on `event.get("simulated", False)`. This flag is **hard‑coded** in the simulator; real traffic will be ignored. |
| **ML anti‑pattern** | **Single‑event inference** (no batch). |
| **Security** | **No device selection** – always CPU (`map_location='cpu'`). |

---

## 3️⃣ `inference/enrichment.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 25‑31 | **Deterministic geo‑mapping** uses `hashlib.md5` (non‑cryptographic). |
| 33‑43 | **Intel enrichment only for `high`/`critical` severity** and 40 % chance. |
| 45‑48 | **`await asyncio.sleep(0.005)`** simulates external API latency. |
| 51‑57 | **IP range checks (`192.168.`, `10.`, `172.`)** – missing `172.16‑31` nuance, and IPv6 not considered. |
| 63‑66 | **`evidence` payload is mutated in‑place**. |
| 68‑71 | **Key names include spaces** (`"GeoIP (Source)"`). |
| 72 | **Returns the modified alert dict** – callers must re‑assign it. |
| **Security** | **Deterministic hashing** without a secret salt → predictable mapping. |
| **Performance** | **Hard‑coded 5 ms sleep** will create a **throttling bottleneck** at ~200 evts/sec per worker. |

---

## 4️⃣ `inference/correlation.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 13‑15 | **Redis connection created on each `IncidentCorrelator` init**; no connection pool, no TLS. |
| 15 | **`self.time_window_sec` default 300 s** – hard‑coded sliding window. |
| 22‑25 | **Store each alert as a JSON string in a Redis list**; no size limit. |
| 27‑30 | **Deserialize every alert in the list on each incoming event** – O(N²) as list grows. |
| 32‑41 | **Risk aggregation** – assumes `risk_score` already present. |
| 42‑50 | **Incident generation criteria** (`len(tactics) >= 2 or highest_risk >= 80`). Hard thresholds may cause many false positives or miss subtle multi‑stage attacks. |
| 51‑53 | **`self.redis.delete(key)` after incident creation** – clears *all* alerts for that source IP. |
| 55 | **No error handling on Redis commands**. |
| **Scalability** | **No TTL for the incident hash**. |
| **Security** | **No authentication for Redis**; defaults to no‑auth. |

---

## 5️⃣ `inference/rules.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 1‑2 | **Function returns `list` of dicts**, but no schema validation. |
| 9‑10 | **DDoS rule** checks `event.get("conn_state") == "REJ"` **or** `orig_pkts > 10000`. |
| 25‑27 | **C2 Beaconing heuristic**: tiny repeated payloads on “weird ports”. |
| 38‑42 | **DNS Tunnelling detection**: `len(query) > 60 and qtype_name == "TXT"`. |
| 53‑63 | **Fallback DGA rule** uses `shannon_entropy > 3.8` and `domain_length >= 10`. |
| 66‑78 | **Encrypted‑Traffic Malware rule** looks for JA4 fingerprint starting with `t13d`. |
| 81‑92 | **Reconnaissance rule** (`conn_state == "S0"` and `orig_pkts < 5`). |
| 95‑108 | **Data Exfiltration rule** (`orig_bytes > 5 M` and `resp_bytes < 10 k`). |
| **Overall** | **All rules are static**; no dynamic updates from threat‑intel feeds. |
| **Security** | **No input sanitisation** – `event` dict may contain malicious values that get logged or persisted. |

---

## 6️⃣ `api/main.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 13‑16 | **API key loaded from env (`TSOC_API_KEY`)** – **hard‑coded** in pod spec. |
| 19‑23 | **`secrets.compare_digest`** correctly avoids timing attacks. |
| 31‑38 | **`slowapi` rate limiter**: `key_func=get_remote_address`. No per‑user limit. |
| 43‑47 | **CORS `allow_origins`** reads from env and splits on commas. Default includes `http://localhost:8501`. |
| 49‑52 | **Health endpoint** returns static version. No liveness / readiness probes for DB connectivity. |
| 53‑56 | **Metrics endpoint** placeholder — no real metrics. |
| 58‑65 | **Global exception handler** logs the exception and returns a generic 500. |
| 67‑75 | **DB session lifecycle** – catches generic `Exception` on `yield`. |
| 78‑82 | **`/api/v1/alerts`**: rate limit 50/s, `limit` query param bounded `ge=1, le=1000`. |
| 84‑101 | **`/api/v1/stats`** runs a single DB query with aggregate functions – good, however, no `async` driver. |
| **Security** | **No HTTPS enforcement** – FastAPI runs on plain HTTP behind the service. |
| **Scalability** | **Single DB connection pool** (default `sessionmaker`) may be too small for multiple API replicas. |
| **Logging** | No request‑ID correlation; logs may be interleaved. |

---

## 7️⃣ `api/database.py`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 5‑9 | **`DATABASE_URL` required** – raises on missing env. Good fail‑fast. |
| 10‑14 | **SQLite fallback handling** (`check_same_thread=False`). No migration path from SQLite to Postgres. |
| 15‑18 | **Engine created without `pool_pre_ping`** – stale connections may cause errors after a DB restart. |
| **Overall** | No **SQLAlchemy models** shown, but ensure they use `__table_args__ = {"sqlite_autoincrement": True}` for SQLite. |

---

## 8️⃣ `k8s/soc-deployment.yaml`

| Line(s) | Issue | Why it matters | Fix / mitigation |
|---------|-------|----------------|-------------------|
| 8‑9 | **`replicas: 3`** for stream‑processor, but no **HorizontalPodAutoscaler**. |
| 19‑30 | **Liveness probe** runs `faust -A inference.stream_processor_faust agents`. This spawns a **new Faust process** on every probe! |
| 33‑38 | **Resource limits** (1 CPU, 2 GiB) – may be insufficient for **model inference** at scale. |
| 40‑42 | **`securityContext.readOnlyRootFilesystem: true`** – the container likely needs write access for **model files** (`/models`). |
| 59‑64 | **API deployment**: `X_API_KEY` taken from secret `tsoc-secrets`. Good. |
| 66‑71 | **Liveness & readiness probes** hit `/docs`. This endpoint can be heavy (auto‑generated OpenAPI). |
| **Missing** | No **PodDisruptionBudget** – graceful rolling updates could evict all pods at once. |
| **Missing** | No **network policies** restricting inbound/outbound traffic. |
| **Missing** | No **HPA** for the API deployment. |
| **Missing** | No **TLS** for Redis connection in code. |

---

## 📐 Overall Architecture Findings

| Category | Critical Findings | Likely Impact | Priority |
|----------|-------------------|---------------|----------|
| **Security** | - Plaintext API‑key & Redis credentials.<br>- MD5 used for model integrity & deterministic hashing.<br>- No TLS for Redpanda, Redis, or FastAPI.<br>- DLQ strips forensic fields.<br>- Global exception handler hides useful errors, making debugging harder. | Credential leakage, model tampering, data‑exfil via intercepted traffic. | **High** |
| **Scalability** | - Fixed `concurrency=4` and static pod replica counts.<br>- No back‑pressure or rate‑limiting on enrichment (5 ms sleep).<br>- No HPA, no autoscaling based on Kafka lag.<br>- Per‑event model inferencing (no batching).<br>- Redis list unbounded, O(N²) scans. | Throughput caps at a few hundred events/s; backlog → stale alerts. | **High** |
| **Reliability** | - Liveness probes spawn new Faust processes.<br>- Workers re‑load model on each restart → high churn.<br>- No graceful shutdown flushes for Kafka.<br>- No DB connectivity check in `/healthz`. | Unexpected pod restarts cause alert loss; OOM or crash loops. | **Medium** |
| **Observability** | - No Prometheus metrics for Faust, enrichment latency, Redis lag.<br>- No request IDs across API → hard trace. | Difficult to detect slowdowns, spikes, or failure patterns. | **Medium** |
| **ML Anti‑Pattern** | - Single‑event inference, hard‑coded thresholds, deterministic hashing without secret salt. | Poor detection accuracy, predictable behaviour, inefficiency. | **Medium** |
| **Data Persistence** | - SQLite fallback path not hardened; DB URL required but no migration to Postgres in prod.<br>- No migrations enforced (`Base.metadata.create_all` missing). | Potential data loss or schema drift. | **Low** |

---

## 🎯 Consolidated Recommendations

| Area | Action | Brief Implementation |
|------|--------|----------------------|
| **Secrets & Transport** | Store **API key**, **Redis password**, and **Redpanda credentials** in **K8s Secrets**; use TLS (`rediss://`, `kafka://` with SASL_SSL). | Update `env` sections in `soc-deployment.yaml`; add `valueFrom.secretKeyRef`. |
| **Hashing / Model Integrity** | Replace **MD5** with **SHA‑256** (both for model file verification and deterministic geo/intel hashing). Add a **pepper** from secret. |
| **Model Loading** | Implement **process‑wide singleton** for `DGAClassifier` & `ThreatModelOrchestrator`. Add optional **GPU** support. |
| **Batch Inference** | Collect up to **N=64** events in a buffer, then call `self.model(tensor_batch)`. |
| **Back‑pressure & Timeouts** | Wrap `asyncio.to_thread` calls with `asyncio.wait_for(..., timeout=5)`. |
| **Redis Correlation** | Use a **Redis connection pool** with TLS; enable ACLs. |
| **Correlation Optimisation** | Use **Redis hash** to maintain aggregates and cap list size (`LTRIM`). |
| **Enrichment** | Replace static `await asyncio.sleep` with real external API calls using `httpx.AsyncClient` with timeout, retries, and circuit‑breaker. |
| **K8s Probes** | Export a **`/healthz` HTTP endpoint** in Faust (or use a lightweight shell script that checks process PID). Update probes to use it. |
| **Autoscaling** | Add **HorizontalPodAutoscaler** for both stream‑processor and API based on **CPU** and **custom metric** (Kafka lag). |
| **Observability** | Integrate **Prometheus client** in Faust and FastAPI; add **request‑ID** middleware. |
| **Rate Limiting** | Move **SlowAPI key function** to API‑key‑based limiter; also enforce per‑IP limit as fallback. |
| **TLS for API** | Run FastAPI behind an **Ingress TLS** or sidecar that terminates TLS. |
| **Network Policy & PDB** | Add **NetworkPolicy** restricting pod traffic; add **PodDisruptionBudget** to avoid full outage during updates. |
| **Database** | Switch to **async SQLAlchemy**; enable `pool_pre_ping`; enforce migrations via Alembic. |
| **Logging** | Add **middleware** that injects `X-Request-ID` and logs it. |
| **Testing** | Add **unit tests** for each rule with **property‑based testing** (`hypothesis`). |
| **Documentation** | Generate **OpenAPI spec** and publish in `docs/`. Include security sections (API‑Key, TLS). |

---

## ✅ Task List (ready for you to turn into PR tickets)

| # | Subject (imperative) | Description | Active form |
|---|----------------------|-------------|------------|
| 1️⃣ | **Migrate all secret values to K8s Secrets** | Move `TSOC_API_KEY`, `REDIS_HOST`, `REDIS_PASSWORD`, `REDPANDA_BROKERS`, `REDPANDA_USER`, `REDPANDA_PASSWORD` into `Secret` objects and reference via `envFrom`. |
| 2️⃣ | **Replace MD5 with SHA‑256 and add pepper** | Update `models.py` and `enrichment.py` hashing; load `ENRICH_SALT` from secret. |
| 3️⃣ | **Implement a process‑wide model singleton** | Refactor `DGAClassifier` and `ThreatModelOrchestrator` to use a module‑level cached instance. |
| 4️⃣ | **Add batch inference support** | Create a buffer coroutine that batches events (max 64) and runs a single torch forward pass. |
| 5️⃣ | **Wrap thread calls with timeouts** | Add `asyncio.wait_for` (5 s) around `extract_features`, `evaluate_rules`, and `orchestrator.evaluate`. |
| 6️⃣ | **Add Redis connection pooling & TLS** | Use `redis.from_url(os.getenv("REDIS_URL"))` with TLS and a connection pool; enforce ACLs. |
| 7️⃣ | **Cap Redis alert list & use aggregates** | LTRIM list after each push; store `tactics` and `max_risk` in a hash for O(1) correlation. |
| 8️⃣ | **Replace static enrichment sleep with real async HTTP client** | Use `httpx.AsyncClient` with proper timeouts; add exponential back‑off. |
| 9️⃣ | **Rewrite K8s liveness probes** | Expose a `/healthz` endpoint in Faust (or simple pid check) and point probes to it. |
| 🔟 | **Add HPA for stream‑processor and API** | Create `HorizontalPodAutoscaler` objects based on CPU and custom metric (Kafka lag). |
| 1️⃣1️⃣ | **Instrument Prometheus metrics** | Add counters/histograms for processed events, inference latency, Redis lag, API request latency. |
| 1️⃣2️⃣ | **Enforce per‑API‑key rate limiting** | Change SlowAPI key function; add default per‑IP fallback. |
| 1️⃣3️⃣ | **Secure FastAPI with TLS** | Deploy behind an Ingress with TLS termination; remove plain HTTP exposure. |
| 1️⃣4️⃣ | **Add NetworkPolicy and PDB** | Restrict pod network traffic; ensure at least one replica stays during updates. |
| 1️⃣5️⃣ | **Migrate to async SQLAlchemy** | Replace sync ORM with async engine; enable `pool_pre_ping`. |
| 1️⃣6️⃣ | **Add request‑ID middleware** | Propagate `X-Request-ID` across services and log it. |
| 1️⃣7️⃣ | **Replace MD5‑based deterministic hashing with salted SHA‑256** (duplicate of 2️⃣) – ensure consistency across code. |
| 1️⃣8️⃣ | **Add unit tests for all rule functions** | Use `pytest` + `hypothesis` to cover edge cases and ensure no hidden exceptions. |
| 1️⃣9️⃣ | **Document API schema & security** | Generate OpenAPI spec and publish in `docs/`; note API‑Key required and TLS. |
| 2️⃣0️⃣ | **Review and remove `sys.path.append` hack** | Remove line 12‑13; set proper package installation. |

*All tasks are independent; you can start with the high‑impact security fixes (1‑3) and then move onto scalability (4‑10).* 

---

## 📦 Next Steps

1. **Pick a priority** (e.g., “Add secret handling & SHA‑256”).
2. I can **generate a Git patch** for the chosen change(s) or **create a PR** skeleton.
3. If you want any of the above files **modified now**, just tell me which number(s) and the exact transformation; I’ll emit the updated file content.

Let me know where you’d like to start!