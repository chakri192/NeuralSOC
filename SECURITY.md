# SOC Platform Security Architecture

## 1. Zero-Trust Ingestion & Data Diode Enforcement
This platform is designed to operate strictly behind a unidirectional network data diode.
- **Read-Only Access:** The ingestion layer (`tail_to_redpanda.py`) exclusively reads local metadata logs via `tail -F`. It possesses absolutely no capability to transmit network packets back to the monitored environment.
- **No Decryption:** TLS inspection is explicitly forbidden. Threat inference relies entirely on unencrypted metadata (JA3 fingerprints, SNI, byte distributions).
- **Strict Validations:** All incoming logs are sanitized via `jsonschema`. Malformed payloads are synchronously dumped to `dead_letter_events`, preventing buffer overflows or injection attacks against the ML pipelines.

## 2. ML & Correlation Hardening
Machine Learning models in Python represent a significant attack surface (e.g., Pickle deserialization, OOM crashes).
- **Graceful Fallbacks:** If a Torch artifact fails cryptographic hash verification or platform constraints (ARM64 incompatibility), the pipeline defaults to a deterministic Mock ML classifier rather than crashing.
- **Bounded State:** The `IncidentCorrelator` explicitly limits its tracking dictionary to `max_tracked_ips=5000` with periodic LRU eviction and 5-minute time horizons. This prevents algorithmic complexity (CWE-400) attacks where an adversary spams millions of spoofed IPs to exhaust SOC memory.

## 3. Container Isolation
- **Non-Root Execution:** The provided `Dockerfile` explicitly creates and enforces `USER soc_user (UID:1000)`.
- **Minimal Surface:** The image strips unnecessary package managers (`apt-get` cache cleared).
- **Network Segmentation:** Redpanda brokers require split internal/external listeners to ensure isolated container-to-container backend networks vs. frontend dashboard interactions.

## 4. Subprocess Execution Guardrails
The platform does not rely on active response scripts. There is exactly one subprocess call (`tail -F` in ingestion), which uses safe argument vectors (`['tail', '-F', file_path]`) explicitly preventing shell interpolation or command injection (CWE-78).

## 5. Multi-Tenant Deployment Topology
Section 1's data-diode model has a direct consequence for how this
product deploys across multiple tenants: raw traffic never leaves a
tenant's own premises, so the ingestion pipeline (Faust stream
processor + `api/kafka_sink.py`) runs **per tenant, at their site**, not
as one shared instance multiplexing every tenant's traffic. Only the
API and dashboard (`tsoc-api`, `tsoc-dashboard`) are the shared,
multi-tenant SaaS control plane — see `k8s/soc-deployment.yaml`'s own
top-of-file comment for exactly which workloads belong to which half.
Each tenant's on-prem pipeline authenticates to the shared API with its
own `TSOC_SENSOR_TOKEN` (`api/routes/ingest.py`), which is also the
tenant-isolation boundary itself: a compromised or malicious tenant
pipeline can only ever write data tagged as that tenant (see the
`api/routes/ingest.py`-`docstring` and its regression tests for the
cross-tenant hijack this was previously vulnerable to).

`k8s/soc-deployment.yaml` currently packages both halves as one
manifest set, correct for local development, a demo, or a single
self-hosted customer. Splitting it into a control-plane manifest set
and a per-tenant collector manifest set is the natural next step once a
second real tenant needs onboarding, not something forced now with no
second tenant to actually deploy for.

---

# Security posture

The section above describes design intent. This section is a running,
honest account of what's actually *verified*, how, and what still needs
real infrastructure this project doesn't have — replacing gaps that were
previously only disclosed in commit messages / PR discussion with a
durable pointer any reviewer will actually find.

## Verifying a model artifact's provenance

Every CI run on `main` ([workflow](.github/workflows/ci.yml)) signs each
tracked model file (`models/*.pt`) using **cosign's keyless mode**: the
runner exchanges its GitHub Actions OIDC token for a short-lived
certificate from the public Sigstore Fulcio CA, signs the blob, and the
signature + certificate + a public Rekor transparency-log entry are
bundled into `models/<name>.pt.cosign.bundle`. That bundle is verified
again in the same job and uploaded as part of the `security-reports`
build artifact — it is not committed to the repository (it's a
per-build attestation, not a static file).

To independently verify a specific run's signature yourself:

1. Download `models/*.cosign.bundle` from that run's `security-reports`
   artifact (Actions tab → the run → Artifacts).
2. Install [cosign](https://github.com/sigstore/cosign).
3. Run:

   ```bash
   cosign verify-blob \
     --bundle cnn_dga.pt.cosign.bundle \
     --certificate-identity-regexp "^https://github\.com/chakri192/NeuralSOC/\.github/workflows/ci\.yml@.*$" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     models/cnn_dga.pt
   ```

A successful verification proves that exact file's bytes were produced
and attested by this repository's own CI workflow, on a specific commit
— independent of any secret this project would otherwise have had to
provision and protect.

This replaced an earlier, secret-conditional `cosign verify-blob` step
that never actually ran (no key was ever configured) and a stale
`models/cnn_dga.pt.sig` file left over from before real signing existed,
which was a plain SHA-256 hex digest, not a signature.

## Test coverage

Real coverage as of the last local measurement: **72%** across
`api/`, `inference/`, `shared/`, `ingest/` (142 tests, including a real
Kafka-message → DB → authenticated-API integration suite in
`tests/integration/`, and a subprocess-isolated suite in
`tests/unit/test_boot_time_checks.py` for the import-time checks below).
CI's `--cov-fail-under` gate tracks this, set with a margin below the
local number rather than pinned exactly to it.

`api/kafka_sink.py`'s `run_sink()` consumer loop and
`inference/stream_processor_faust.py`'s `process_traffic` agent — both
previously only exercised end-to-end via `tests/test_load.py`'s real
burst test, with no branch-level unit coverage of their own — are now
driven directly: `run_sink()` via a fake `KafkaConsumer` whose `poll()`
sends the test process a real `SIGINT` once its scripted messages are
exhausted (the loop has no other externally-settable stop condition);
`process_traffic` via Faust's `Agent.fun`, which reaches the original
undecorated async function so it can be called with a fake async
stream, no live Faust app or broker required.

The thinnest remaining area is `shared/data_access.py`'s polling-loop
internals beyond the config-loading and health-flagging paths already
covered.

## Dependency scanning

A one-time `pip-audit` sweep brought the full dependency tree to zero
known vulnerabilities. [Dependabot](.github/dependabot.yml) now runs
weekly against both the `pip` and `github-actions` ecosystems so that
state doesn't silently rot the next time a new CVE is disclosed against
something already pinned here.

## K8s manifest validation and live enforcement

Every manifest in `k8s/*.yaml` is checked with
[`kubeconform`](.github/workflows/ci.yml) on every CI run
(`-ignore-missing-schemas` skips CRDs with no public schema — Cilium
`CiliumNetworkPolicy`, Kyverno `ClusterPolicy`, Prometheus
`ServiceMonitor`). This confirms every manifest is structurally valid
Kubernetes YAML; it does not by itself confirm runtime enforcement.

Runtime enforcement of the two highest-stakes manifests has been
verified directly against a real local cluster (`kind` + Cilium as the
CNI, matching this repo's `CiliumNetworkPolicy` usage, + Kyverno
installed via its official Helm chart) — not just schema-checked:

- **`k8s/network-policies.yaml`**: from a pod labeled
  `app: tsoc-stream-processor` with the real policy applied, a raw TCP
  connection to `169.254.169.254:443` (the cloud-metadata range this
  policy's `except` clause excludes — the exact class of bug the
  original audit found, where a "deny" policy was actually an unrestricted
  allow rule to this range) timed out — silently dropped at the CNI layer.
  Default-deny was confirmed separately: an unlabeled pod could not reach
  a plain target pod at all, and only a pod labeled to match
  `ingress-nginx` (in a namespace labeled accordingly) could reach the
  `tsoc-api`-labeled pod's port 8000 — an unlabeled pod could not.

  The same test round also found a second, real gap: the same
  stream-processor pod could reach `1.1.1.1:443` — an arbitrary public
  IP, not just the FQDN-pinned threat-intel API
  (`k8s/cilium-identity-policy.yaml`'s `toFQDNs` rule) it's meant to call.
  Cause: `network-policies.yaml` and `cilium-identity-policy.yaml` both
  select the same pods, and Cilium enforces the *union* of every
  applicable policy regardless of kind — `network-policies.yaml` used to
  carry its own broad `ipBlock: 0.0.0.0/0 except <private ranges>` egress
  rule (and equally broad `ipBlock: 10.0.0.0/8` kubelet-probe ingress
  rules), each wider than the equivalent Cilium rule and each silently
  overriding it. Fixed by removing the CIDR-based versions of these three
  rules from `network-policies.yaml` entirely — kubelet-probe ingress and
  threat-intel egress now live *only* in the tighter Cilium policy
  (`fromEntities: [host, remote-node]` and `toFQDNs` respectively).
  Re-verified against a fresh cluster after the fix: `1.1.1.1:443` now
  times out identically to the metadata range, while `ipwho.is:443` (the
  actual intended destination) still connects successfully.
- **`k8s/kyverno-verify.yaml`**: applying a pod with a mutable image tag
  and no `imagePullPolicy: Always` into the `tsoc` namespace was rejected
  by the admission webhook with both rules' exact validation messages
  (`require-digest-pin`, `require-signed-images`). The identical pod spec
  applied to `kube-system` was allowed — confirming the namespace-scoping
  fix actually prevents the cluster-wide outage the original,
  cluster-wide version of this policy would have caused (CoreDNS,
  ingress-nginx, cert-manager, and the CNI itself all run unpinned,
  non-`Always` images there). A pod using a real digest reference and
  `imagePullPolicy: Always` in `tsoc` was allowed.

This was originally a one-time interactive verification on a
single-node cluster. `scripts/verify_multi_node_cluster.sh` now
automates the NetworkPolicy/Cilium half of it on a real 3-node cluster
(1 control-plane + 2 workers) instead, with the test pods deliberately
scheduled onto *different* nodes — a single-node run can't catch a
policy that only worked because every pod shared one node's Cilium
agent state. It also verifies `k8s/hpa.yaml`'s plain
HorizontalPodAutoscaler definitions actually scale a workload under
real CPU load, not just that they're schema-valid. Run via
`.github/workflows/multi-node-cluster-verify.yml` (manually, or weekly)
rather than on every push — standing up kind+Cilium+metrics-server
takes several minutes, which is fine for a scheduled check but not for
gating every commit.

Genuinely not covered by that script (see its own header/summary
output): KEDA/Kafka-consumer-lag-based scaling (the stream-processor's
`ScaledObject`, which needs a real KEDA install and a real Kafka
deployment generating real lag) and Kyverno admission control (still
only verified the original, one-time, interactive way described above
— admission control doesn't depend on which node a pod lands on, so a
multi-node re-run wouldn't add new information the way the
NetworkPolicy re-run does). Reproducible interactively the same way as
before: `kind create cluster` (CNI disabled) → `cilium install` →
apply `network-policies.yaml` + `cilium-identity-policy.yaml` → `helm
install kyverno` → apply `kyverno-verify.yaml` → the connectivity/
admission tests described above.

## TLS: internal service mTLS vs. public ingress

This product changed shape from a single-tenant, on-prem appliance
(deployed behind a client's own data diode, never internet-facing) to a
multi-tenant SaaS (one shared API and dashboard, reached by many client
organizations' employees and sensors over the public internet). Two
different CAs now exist for two different jobs, and it matters not to
mix them up:

- `k8s/cert-manager-internal-ca.yaml`'s cluster-local CA (a one-time
  self-signed bootstrap issuer signs a root CA certificate; a second
  `ClusterIssuer` of kind `ca` issues real workload certificates from
  that root) is for **internal, service-to-service** TLS only —
  currently `tsoc-redis-client-cert`, this API's client certificate for
  mutual TLS to Redis. Nothing outside the cluster ever needs to trust
  this CA, so a publicly-trusted certificate would be the wrong tool for
  this job regardless of domain ownership.
- `k8s/cert-manager-public-ca.yaml`'s `letsencrypt-prod` `ClusterIssuer`
  is for **public-facing** ingress — `k8s/ingress.yaml`'s
  `tsoc-api-ingress` and `tsoc-dashboard-ingress` both reference it now.
  Unlike the appliance model, real employees' browsers and real tenant
  sensors connect over the open internet and need a certificate their
  own trust stores already recognize; a private CA can't provide that.
  This issuer only works once `api.tsoc.local`/`app.tsoc.local` are
  replaced with real, DNS-resolvable hostnames pointed at the ingress
  controller's public load balancer — ACME HTTP-01 validation fails
  against a placeholder or unresolvable domain, exactly as it did the
  one time `letsencrypt-prod` was pointed at `api.tsoc.local` in the
  earlier, still-internal-only version of this file.

Verified against a real cert-manager installation (Helm chart, a fresh
`kind` cluster): the internal bootstrap issuer, root CA certificate, and
workload issuer all reached `Ready`, and a real `Certificate` requested
for `api.tsoc.local` under that internal issuer was issued —
`kubectl get secret ... | openssl x509 -noout -issuer -ext subjectAltName`
showed `issuer=CN=tsoc-internal-ca` and `DNS:api.tsoc.local`, a genuine,
cluster-trusted X.509 certificate. `letsencrypt-prod` itself is not
independently verifiable in this sandbox (it needs a real, publicly
delegated domain and a reachable ingress controller) — the config is
externally consistent with cert-manager's documented ACME HTTP-01 solver
shape, but treat it as unverified until exercised against a real domain.

## Boot-time configuration checks

Two misconfigurations fail the process at import time rather than
degrading silently:

- `TSOC_JWT_SECRET`, if set, must be ≥32 bytes (RFC 7518 §3.2 minimum for
  HS256) — [api/auth.py](api/auth.py) raises `RuntimeError` at import if
  it's shorter, rather than relying on PyJWT's own `InsecureKeyLengthWarning`
  (a warning, not a boot failure) at first encode/decode. An entirely
  *unset* secret still fails lazily, on first use — a deployment using
  only the static service key was never required to configure one.
- `DB_SSLMODE` for a `postgresql://` `DATABASE_URL` must be `require`,
  `verify-ca`, or `verify-full` — [api/database.py](api/database.py)
  raises at import on `disable`/`allow`/`prefer` instead of silently
  allowing an unencrypted or unverified connection.

## Secrets provisioning

[k8s/secrets.yaml.example](k8s/secrets.yaml.example) is a template only
-- `k8s/secrets.yaml` (gitignored) is never meant to hold real values in
git history, not even encrypted-at-rest in a private repo. Recommended
path, lowest-friction to bootstrap since it needs no pre-existing Vault:
[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets).

1. Install the controller once per cluster: `helm install sealed-secrets
   sealed-secrets/sealed-secrets -n kube-system`. It generates its own
   asymmetric keypair on first install and never exposes the private
   half outside the cluster -- only it can decrypt what `kubeseal` below
   encrypts.
2. Populate a real, local `k8s/secrets.yaml` from the example (never
   committed).
3. `kubeseal --format yaml < k8s/secrets.yaml > k8s/sealed-secrets.yaml`
   -- this calls the live controller's public key over the cluster API,
   so it must run against the target cluster (or with `--cert` pointed
   at a fetched copy of that public key for offline sealing). The
   output is ciphertext a `SealedSecret` custom resource wraps; this
   file is safe to commit and is what actually gets checked in and
   applied (`kubectl apply -f k8s/sealed-secrets.yaml`), not
   `k8s/secrets.yaml` itself.
4. The controller watches for `SealedSecret` resources and decrypts each
   into the plain `Secret` (`tsoc-secrets`) every workload in this repo
   already reads from -- no application code or manifest changes needed
   beyond this substitution.

This hasn't been exercised against a real cluster in this repo (no live
cluster available in this environment, and `kubeseal` needs one to
encrypt against) -- treat the command sequence above as the documented
procedure, not something independently verified here the way the
NetworkPolicy/Kyverno sections above were.

## Secret rotation

- `TSOC_JWT_SECRET` and `REDIS_PASSWORD`: rotate every 90 days via Vault
  (see [README](README.md#security-hardening-post-audit-remediation)).
- DLQ overflow: if a local-disk DLQ fallback exceeds its configured max
  size, alert on-call and rotate manually.

## Access control

[dashboard/app.py](dashboard/app.py) and
[terminal/tsoc_console.py](terminal/tsoc_console.py) both require a real
per-employee account -- email + argon2-hashed password, issued a scoped,
expiring JWT by [api/routes/auth.py](api/routes/auth.py)'s `/auth/login`.
`api/deps.py`'s `require_scope`/`scope_to_tenant` enforce that JWT's
`tenant_id` on every request that carries it through to the API, and
every caller of the API now does carry it through:
[terminal/tsoc_console.py](terminal/tsoc_console.py),
[dashboard/pages/command_center.py](dashboard/pages/command_center.py)'s
triage actions, and (as of
[dashboard/session_data.py](dashboard/session_data.py)) the dashboard's
own read pages (alerts, incidents, stats, network, health) all read and
write using the logged-in employee's own per-tenant JWT
(`st.session_state["access_token"]`), not a shared credential. Login is
rate-limited and lockout-protected (5 failed attempts / 15 min), and
logout revokes the specific token via a Redis-backed denylist rather
than only relying on its natural expiry.

Those same four dashboard pages previously read through
[shared/data_access.py](shared/data_access.py)'s module-level
`stream_manager` singleton instead -- a process-wide client
authenticated with one static, all-tenant `TSOC_API_KEY`, so every
logged-in employee saw every tenant's alerts/incidents/stats regardless
of which tenant they actually belonged to, a real cross-tenant data
leak. `dashboard/session_data.py` replaced that singleton with a
per-session client (`st.cache_data`-cached per-token, so different
employees' cached reads never mix) for exactly those four pages;
`stream_manager` itself still exists and is still correct for
[dashboard/cli_dashboard.py](dashboard/cli_dashboard.py)'s
single-operator terminal tool, which was never part of this leak in the
first place (there's only ever one credential and one operator using
it). Regression-tested directly in
`tests/unit/test_session_data.py::test_different_tokens_never_see_each_others_cached_data`,
and verified end-to-end against a running dashboard (login state seeded
via `dashboard/_seed_dev.py`): all four pages render correctly from a
session's own token, and a triage action attributes correctly to that
session's analyst.

There is no in-app account-creation UI beyond
`POST /api/v1/auth/signup` (a brand-new tenant's first admin -- the only
path around the auth system's own chicken-and-egg problem, since
`/auth/login` needs an existing user and the invite endpoint needs an
existing admin) and `POST /auth/tenants/{id}/users/invite` (admin-only,
for every account after that).

[dashboard/cli_dashboard.py](dashboard/cli_dashboard.py) is the
exception: a read-only ops view (no triage actions, no tenant data
isolation) still gated behind a single shared credential
(`secrets.compare_digest`, resolved through
[shared/auth.py](shared/auth.py)) rather than a per-employee account.
That gate is mandatory, not opt-in: set `DASHBOARD_PASSWORD` for a
persistent password, or leave it unset and it defaults to `user`/`user`
-- a printed console warning names that default explicitly every time
it's in use, so it's never silently relied on. Set a real
`DASHBOARD_PASSWORD` before this interface is reachable by anyone other
than the person running it locally; if it's ever exposed to more than a
small trusted ops team, put a real auth layer (SSO via an Ingress, e.g.
oauth2-proxy) in front of it instead, the same way any other
internal-only tool would be.

## Ops hardening: audit log, admin MFA, per-tenant rate limiting

Three pieces of Phase 6 ops hardening, all shipped:

- **Audit log** ([api/audit.py](api/audit.py), `GET /api/v1/audit` in
  [api/routes/audit.py](api/routes/audit.py)): who did what, when, per
  tenant. `record_audit_event()` is called from every route that
  changes state or represents an auth event -- login (success, failure,
  lockout, MFA challenge/failure), signup, invite, password reset,
  sensor-token creation, and triage updates. Best-effort by design: a
  write failure is logged and swallowed, never breaking the action it
  describes. Reading it requires `users:manage` (the same scope as
  inviting/deactivating teammates) and is tenant-scoped like every other
  route.
- **Per-tenant rate limiting** (`api/deps.py`'s `get_tenant_aware_key`):
  the alerts/stats/triage routes key their rate limit on the caller's
  `tenant_id` (decoded from their JWT) instead of source IP, so one
  noisy or abusive tenant's employees can't exhaust a budget shared with
  every other tenant whose employees happen to request from the same IP
  range (a corporate NAT gateway, a shared VPN egress). `/auth/*` and
  `/ingest/alerts` stay IP-keyed -- identity isn't established yet at
  login, and a sensor token isn't a JWT to decode a tenant_id from
  without a DB lookup on every rate-limit check.
- **Optional TOTP MFA for admin accounts** (`api/routes/auth.py`'s
  `mfa_*` endpoints): scoped to `users:manage` like invite/sensor-token
  creation, so only admin accounts can enroll -- they're the highest-
  value target, since they can invite or deactivate other users. Enroll
  generates a secret but doesn't activate it; confirm requires proving a
  real code from the authenticator app first. Once enabled, `/auth/login`
  returns a short-lived challenge (`mfa_required: true`, `mfa_token`)
  instead of a session, and `POST /auth/mfa/verify` exchanges that plus
  a current code for the real token. Disabling MFA requires a current
  code too, not just the session token, so a hijacked session alone
  can't turn off the control that matters most for that account.

  [dashboard/app.py](dashboard/app.py)'s login form handles the
  challenge (a second "enter your code" step). No enrollment UI exists
  in either client yet -- `dashboard/pages/admin.py` (a general
  security-settings panel) was never built, so `scripts/enroll_admin_mfa.py`
  is the only way to turn MFA on today, mirroring
  `scripts/bootstrap_tenant.py`'s role for tenant creation.
  [terminal/tsoc_console.py](terminal/tsoc_console.py) has no
  code-entry screen for the challenge at all -- an MFA-enabled admin
  logging in there gets a clear "sign in via the web dashboard instead"
  message rather than a crash, but can't actually complete login from
  the terminal.

## Genuinely out of scope here

- **A genuinely offline/air-gapped signing key**, as opposed to the
  keyless Sigstore flow above (which depends on reaching the public
  Fulcio/Rekor services from the CI runner or verifier). `scripts/sign_manifest.py`
  documents this alternative and correctly refuses to run without a real
  persistent key rather than fabricate one.
- **A persistent, CI-integrated live cluster.** The NetworkPolicy/Kyverno
  enforcement described above was verified interactively against a real
  local cluster, not asserted from schema validation alone — but that
  cluster isn't kept running or wired into CI, so a manifest change after
  this was written isn't automatically re-verified at that level (schema
  validation via `kubeconform` still runs on every push).
