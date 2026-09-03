# TSOC Enterprise Hardening Sprint — Line-by-Line Audit (Live System)
Saved: 2026-09-03
Repo: /Users/chakri/Downloads/hackaton/project
Branch: main (cea1596 — final DevSecOps push)

## Scope
- inference/stream_processor_faust.py, correlation.py, models.py, rules.py, features.py, enrichment.py, schemas.py, feature_extractor.py, risk.py, stream_processor.py, train_model.py
- api/main.py, database.py, schemas.py, models.py, kafka_sink.py
- ingest/simulator.py, pcap_ingester.py, tail_to_redpanda.py
- shared/data_access.py, schemas.py, formatters.py
- k8s/network-policies.yaml, services.yaml, soc-deployment.yaml, ingress.yaml, secrets.yaml, hpa.yaml, pdb.yaml
- docker-compose.yml, .env, Dockerfile, requirements.txt, Makefile
- dashboard/app.py, pages/*.py
- .github/workflows/ci.yml
- tests/test_pipeline.py, tests/unit/test_ui_shared.py

## Key Findings (exact file + line + snippet + fix)

### 1. Redis / Faust Race Conditions
- correlation.py:30-54 — read-modify-delete race; multi-worker concurrent lpush/lrange/delete causes data loss/duplicates.
- correlation.py:14 — ConnectionPool missing socket_timeout/socket_connect_timeout; threads block forever.
- stream_processor_faust.py:45 — ThreadPoolExecutor(max_workers=16) with cpu:1000m = severe overcommit.
- stream_processor_faust.py:102-107 — run_in_executor on correlation lacks timeout; blocking will stall agent.

### 2. FastAPI Async Block / Validation Bugs
- api/main.py:59-65 — @app.exception_handler(Exception) catches RequestValidationError -> 500 instead of 422.
- api/main.py:41-47 — CORS allow_credentials=True + allow_methods=["*"] + allow_headers=["*"] too permissive.
- api/main.py:49-55 — /metrics and /healthz unprotected by limiter or auth; /metrics returns false placeholder.
- api/database.py:15 — create_engine missing pool_pre_ping=True; stale Postgres connections cause 500 after restart.

### 3. PyTorch / Heuristic Edge Cases
- inference/models.py:68 — domain.lower() only; IDNA normalization (patch_memory_audit.py targeted _encode which doesn't exist) missing; unicode homoglyphs / punycode traverse as padding (0).
- inference/models.py:78-79 — shape guard unreachable because truncated at 69-71; silent truncation hides data drift.
- inference/rules.py:10,27,83,99 — direct event field reads without safe_int/safe_float; TypeError on string-formatted Zeek values.
- inference/rules.py:53-63 — DGA fallback threshold too low; high false positive on legitimate random subdomains.
- inference/features.py:117-200 — feature_extractor.py (BeaconingTracker, ReconScanTracker, lookup_ja3) is entirely dead code; not imported anywhere.

### 4. Kubernetes YAML Misconfigurations
- k8s/soc-deployment.yaml:22-27 — livenessProbe httpGet /healthz port 8000; Faust has no HTTP. CrashLoopBackOff guaranteed.
- k8s/services.yaml:13-22 — tsoc-stream-processor-service targets port 8000 but Deployment has no ports defined.
- k8s/network-policies.yaml:14-46 — stream-processor-allow uses podSelector app: redis / app: redpanda but those labels never exist in repo; default-deny-all blocks all egress.
- k8s/network-policies.yaml:49-92 — api-allow ingress from redis/postgres (they never call API); egress to redpanda:9092 unnecessary for API.
- k8s/ingress.yaml:1-19 — ssl-redirect true but no tls / secretName; redirect to nonexistent HTTPS.
- k8s/secrets.yaml:6-8 — api-key: changeme-in-production hardcoded and git-tracked.
- k8s/hpa.yaml:1-18 — only CPU metric; memory not scaled despite 2Gi limit.

### 5. PII / Weak Crypto / Input Validation
- shared/data_access.py:17 — API_KEY fallback = "tsoc-prod-key-2026" hardcoded in source.
- inference/schemas.py:5 — IP_REGEX allows invalid IPs (999.999... , ... , abcd).
- inference/enrichment.py:51 — RFC 1918 check lacks 172.16-31; 172.32+ treated as external.
- api/kafka_sink.py:49-63 — empty alert_id causes IntegrityError; rollback drops entire batch (up to 100).
- dashboard/app.py:15-26 — external call to github.com on every Streamlit rerender; leaks commit SHA.
- ingestion: simulator.py (dga_domains include xn-- fake), pcap_ingester.py (no max packet size), tail_to_redpanda.py (line 21 value_serializer can emit non-dict bytes).

### Verification Performed (live system reads)
- model hash matches (models/cnn_dga.pt.sha256 == shaft256sum of .pt); good.
- .env is gitignored (not tracked); good.
- redis compose has NO auth / TLS (docker-compose.yml); bad.
- sklearn/pandas only used in dashboard pages; not in inference pipeline.
- idna never imported in production code; only in failed patch script.
- stream_processor_faust.py never called by Dockerfile/Makefile; Dockerfile calls stream_processor.py.
- feature_extractor.py never imported; dead code.
- risk.py calculate_risk_score imported by correlation.py but never called in correlation logic (line 40 reads r.get("risk_score") but add_alert never computes it from calculate_risk_score).
-ENDOFFILE
echo "Written $(wc -l < /Users/chakri/Downloads/hackaton/project/audit/final-code-teardown.md) lines to audit/final-code-teardown.md"
ls -la /Users/chakri/Downloads/hackaton/project/audit/