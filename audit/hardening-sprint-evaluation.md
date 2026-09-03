# Hardening Sprint Re-Evaluation (live filesystem, 2026-09-03)

Ratings re-derived strictly from files on disk today. Scale: 1 = toy, 10 = production-grade.

| Area | Rating | Verdict |
|---|---|---|
| Kubernetes manifests | 5/10 | Real zero-trust primitives, but policies contradict the actual traffic and the set is not deployable standalone |
| Docker-Compose (dev stack) | 3/10 | Broken YAML — three top-level `volumes:` keys; `docker compose config` will not parse |
| CI/CD pipeline | 4/10 | Bandit + Trivy present but non-blocking; no test/build/deploy jobs |
| FastAPI service | 6/10 | Solid auth + rate limiting + fail-fast DB; env-var mismatch breaks k8s boot |
| Faust stream processor | 6/10 | Good concurrency, 5s timeout, PII-stripped DLQ; env fallback and probe are weak points |
| ML model loading | 4/10 | SHA-256 integrity + mock fallback is good; gated to simulated events, half the pipeline is dead code |
| Overall infrastructure hardening | 6/10 | Direction is right; gaps are integration/consistency, not ambition |

---

## Kubernetes manifests — 5/10
Files: `k8s/soc-deployment.yaml`, `k8s/hpa.yaml`, `k8s/pdb.yaml`, `k8s/network-policies.yaml`

Strengths:
- `securityContext`: `readOnlyRootFilesystem: true`, `runAsNonRoot: true` on both deployments (soc-deployment.yaml:39-42, 80-83)
- Resource requests + limits on the stream processor (33-38); CPU HPA at 70% utilization, 2-10 / 2-6 replicas (hpa.yaml); PDBs with `minAvailable: 1` (pdb.yaml)
- `default-deny-all` ingress + egress (network-policies.yaml:1-12)
- API key injected via `secretKeyRef` (soc-deployment.yaml:59-63)

Defects:
- Stream-processor ingress allows only `app: redpanda` pods, but the deployment's broker env points to the Service `soc-redpanda-cluster.prod.svc.cluster.local:9092` (soc-deployment.yaml:19-20 vs network-policies.yaml:18-30). Same for the API: ingress allows only redis/postgres pods, so nothing can reach the API at all (network-policies.yaml:41-60).
- Stream-processor egress omits Redpanda; API egress omits Redpanda even though `api/kafka_sink.py` consumes from it.
- No Service, Ingress, Secret, ConfigMap, or Namespace manifests. `tsoc-secrets` is referenced but never defined; port 8000 is unreachable. The set cannot be applied standalone.
- API deployment has no `resources` block.
- Liveness probe runs `faust -A inference.stream_processor_faust agents` — a new Faust process per probe (soc-deployment.yaml:22-29).
- `default-deny-all` is namespaced `default`; the allow policies carry no namespace metadata.

## Docker-Compose (dev stack) — 3/10
- Structurally broken: three separate top-level `volumes:` keys at column 0 (lines 54, 64, 69). Postgres `volumes`, `healthcheck`, and `networks` are nested under the first `volumes:` key instead of under the `postgres` service (lines 55-62) — silently detached.
- Plaintext fallback survives the env-var change: `POSTGRES_PASSWORD: ${COMPOSE_POSTGRES_PASSWORD:-secure_soc_password}` (line 40). `.env` still holds the plaintext password (line 9) — git-ignored, so acceptable, but the compose default is not.
- `platform: linux/arm64` hardcoded; redis declares `networks: [soc-net]` while postgres/redpanda do not.
- Positives: Redpanda pinned to `v23.3.11`, split internal/external listeners, transactions + idempotence enabled, healthchecks present.

## CI/CD pipeline — 4/10
- Bandit (`bandit -r . -ll`) and Trivy `fs` scan filtered to `HIGH,CRITICAL` are present, both uploading JSON artifacts.
- Neither is a gate: Bandit runs with `|| true` (line 29); Trivy has no `exit-code`. This is artifact collection, not a gate.
- No test job at all. `tests/test_pipeline.py` contains only `assertTrue(True)` (line 5) and is never executed in CI.
- No build, container push, deploy, secret scanning (gitleaks/trufflehog), or dependency-pinning check.

## FastAPI service — 6/10
- API-key auth via `APIKeyHeader` + `secrets.compare_digest` (main.py:19-26) — constant-time, good.
- `slowapi` rate limiting at 50/s; strict `Query(100, ge=1, le=1000)` bounds; consolidated stats query; global exception handler suppressing stack traces (main.py:59-65); `database.py` fails fast on missing `DATABASE_URL`.
- Deployment-breaking bug: the app reads `os.getenv("TSOC_API_KEY")` (main.py:14), but the k8s deployment injects env var `X_API_KEY` (soc-deployment.yaml:59). The app raises `RuntimeError` at boot under that manifest.
- CORS is credentialed *and* wildcard: `allow_credentials=True` with `allow_methods=["*"]`, `allow_headers=["*"]` (main.py:41-47).
- `/metrics` returns hard-coded zeros (main.py:53-55) despite the Prometheus comment.
- Readiness probe hits `/docs` (Swagger UI), which returns 200 regardless of health.

## Faust stream processor — 6/10
- `@app.agent(..., concurrency=4)`; feature extraction, rules, and ML dispatched to a bounded `ThreadPoolExecutor(max_workers=16)` wrapped in `asyncio.wait_for(..., timeout=5.0)` (lines 97-107) — genuine anti-stall hardening.
- DLQ routing with PII sanitization before dead-lettering (strips `id.orig_h`, `id.resp_h`, `uid`, `payload`) — lines 130-133.
- Schema validation before publish, structured JSON logging, `on_stop` graceful shutdown, component singletons built once on startup.
- Gaps: broker URL falls back to `127.0.0.1:9092` rather than failing fast; topics defined without `num_partitions`; module-global `executor` never shut down; k8s liveness probe re-spawns a Faust process; no alert deduplication before publish.

## ML model loading — 4/10
- `DGAClassifier` computes SHA-256 of `cnn_dga.pt` and compares against `cnn_dga.pt.sha256`, raising on mismatch and falling back to a deterministic mock — good supply-chain practice (models.py:35-51). The hash on disk matches the file today (`ceb43973…`).
- The autoencoder path has no integrity check at all — `dl_engine.py` loads `autoencoder_flow.pt` via plain `torch.load`/`load_state_dict` with no hash verification.
- `DeepLearningEngine` is dead code — nothing imports `dl_engine` anywhere in the repo. The autoencoder branch is never exercised.
- The ML model is gated to simulated events: `if not event.get("simulated", False): return ml_alerts` (models.py:99). On real production traffic the classifier silently never fires.
- `torch.load` without `weights_only=True`; fallback hash is a hard-coded string literal.

## Overall infrastructure hardening — 6/10
The sprint moved the needle in the right direction: default-deny network policies, non-root read-only containers, secret-injected API key, CPU HPA, PDBs, 5s ML timeouts, PII-stripped DLQ, schema validation, SHA-256 model integrity, rate limiting, and a global crash guard.

What caps the score: the pieces do not compose. The dev stack YAML does not parse; the k8s API cannot be reached and the stream processor cannot see its broker under the policies meant to protect them; the API boots with a different env var than the manifest provides; CI scans but never gates or tests; and the headline ML model is switched off outside of demo data. Fix those five integration gaps and this is an 8. As committed, 6/10.
