# Integration & Bug-Squashing Sprint Verification (live filesystem)

Re-check of the 5 previously-found blockers, plus residual issues. Scale: 1 = toy, 10 = production-grade.

## Blocker-by-blocker verdict

| # | Blocker | Status | Evidence |
|---|---|---|---|
| 1 | docker-compose YAML + plaintext passwords | **FIXED** | Single `volumes:` (line 63), single `networks:` (line 69); `POSTGRES_PASSWORD: ${COMPOSE_POSTGRES_PASSWORD}` with no `:-fallback` (line 40) |
| 2 | NetworkPolicies: external API ingress + Redpanda egress | **FIXED (with caveats)** | `namespaceSelector: {}` added to API ingress (line 67); Redpanda egress added to both stream-processor (40-46) and API (84-90) |
| 3 | `TSOC_API_KEY` env var + API resource limits | **PARTIAL** | Env var fixed (soc-deployment.yaml:59 ↔ api/main.py:14). **API deployment STILL has no `resources` block** |
| 4 | Bandit + Trivy as strict blocking gates | **FIXED** | Trivy `exit-code: 1` (ci.yml:44); Bandit `|| true` removed (ci.yml:29) — both now fail the run on findings |
| 5 | `simulated` traffic guard deleted | **FIXED** | `if not event.get("simulated", False): return` removed from models.py:95-100; model now scores all DNS events |

## Residual issues found

- **k8s port mismatch (new, medium):** stream-processor env points to broker on `:9092` (soc-deployment.yaml:20), but both the stream-processor ingress (line 31) and egress (line 46) policies permit only port `29092`. One of the two is wrong; as written, default-deny would block the worker from its broker.
- **API external ingress is over-broad (medium):** `namespaceSelector: {}` permits ingress from *every* namespace, not just the ingress controller's. No Ingress/Service/Secret/ConfigMap manifests exist, so `tsoc-secrets` is still referenced but never defined and port 8000 has no exposed Service.
- **`.env` still holds plaintext password (low):** `COMPOSE_POSTGRES_PASSWORD=secure_soc_password` (.env:9). Git-ignored, so not a repo leak, but it is a plaintext secret on disk. Removing the compose fallback also means a missing `.env` now hard-fails postgres boot instead of silently defaulting.
- **`DeepLearningEngine` still dead code (low):** nothing imports `inference/dl_engine.py`; the autoencoder path remains unwired and has no SHA-256 integrity check (unlike cnn_dga.pt).
- **`torch.load` without `weights_only=True` (low):** deserialization risk remains in models.py:47.
- **CI still has no test/build/deploy job** (low): `tests/test_pipeline.py` is a stub (`assertTrue(True)`) and is never executed by the pipeline.
- **API hardening leftovers:** CORS is credentialed + wildcard (main.py:41-47); `/metrics` returns hard-coded zeros (main.py:53-55); readiness probe hits `/docs`, which returns 200 regardless of health.

## Final ratings

| Area | Score | Note |
|---|---|---|
| Kubernetes manifests | 6/10 | External ingress + Redpanda egress fixed; API deployment still unresourced; port 9092/29092 mismatch; no Service/Secret/Ingress |
| Docker-Compose (dev stack) | 7/10 | YAML structurally sound; plaintext fallback eradicated; `.env` plaintext remains on disk |
| CI/CD pipeline | 6/10 | Both scanners now blocking gates; still no test/build/deploy jobs |
| FastAPI service | 7/10 | Env-var mismatch fixed; CORS, fake /metrics, and /docs probe remain |
| Faust stream processor | 6/10 | Unchanged from last sprint; concurrency, 5s timeout, PII-stripped DLQ hold |
| ML model loading | 6/10 | `simulated` guard deleted — model now scores live DNS events; autoencoder path still dead code |
| **Overall infrastructure hardening** | **7/10** | |

## Ultimate verdict

**7/10 — production-credible, not production-ready.**

The integration sprint cleared four of the five blockers cleanly and the fifth partially. The architecture is now coherent end to end: a zero-trust default-deny mesh, non-root read-only containers, secret-injected API key, CPU-driven autoscaling with disruption budgets, blocking vulnerability gates, schema-validated alerts with a PII-sanitised dead-letter queue, and a cryptographically integrity-checked ML model that actually fires on live traffic. That is a real, defensible SOC platform.

What keeps it off production status is not ambition but residue: the k8s broker port mismatch that would silently break the worker under default-deny; an API deployment with no resource limits; an external ingress rule so broad it is effectively a public allow; and the missing Service/Secret/Ingress manifests that make the k8s set non-runnable standalone. Fix those four, delete the dead `dl_engine`, and this is a 9.
