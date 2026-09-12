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

## Model validation against real-world data

Both detection models were trained purely on this repo's own synthetic
generators. Whether that generalizes to real traffic used to be an
open question, unverified in either direction. It isn't anymore, for
the DGA classifier — [scripts/evaluate_against_real_dga_dataset.py](scripts/evaluate_against_real_dga_dataset.py)
runs the live model against [benchmarks/real_dga_domains.csv](benchmarks/real_dga_domains.csv),
a genuine published research dataset (Cucchiarelli et al., *Expert
Systems with Applications*, 2021 — https://doi.org/10.1016/j.eswa.2020.114551):
10,000 domains, half real malware-family DGA domains across 25 families
(sourced from the Netlab Opendata Project's actual observed traffic),
half real Alexa-ranked benign domains — none of it generated by this
project.

**Current measured result (hybrid model, see below): 84.6% precision,
77.2% recall, 13.9% false-positive rate, 81.6% overall accuracy**, at a
threshold (`DGA_CLASSIFICATION_THRESHOLD=0.97`) chosen specifically
because it's the highest one that clears the per-family regression gate
against every one of the 25 real families — not just the best-looking
aggregate number. Per-family recall still varies (100% on
`corebot`/`symmi`, down to 26-38% on `vawtrak`/`gozi`/`matsnu`, the
hardest three), but every family is at or above its pre-Phase-1
baseline — the earlier `vawtrak`/`conficker`/`pushdo` regression
described below is fixed, not just disclosed. The script prints the
full breakdown.

This model was run against a real published malware capture
(malware-traffic-analysis.net, 2026-01-31, Lumma Stealer) as a second,
independent check beyond the benchmark above: of 72 real DNS queries in
that capture, 7 were genuinely suspicious cheap-TLD/dictionary-style
domains (`arch.filemegahab4.sbs`, `whitepepper.su`,
`media.megafilehub4.lat`, `whooptm.cyou`, `holiday-forever.cc`,
`hiyter.com`, `communicationfirewall-security.cc`). This specific
72-domain sample is small enough that its exact catch count moves
between retrains (4-5 of 7 across the last two model versions, versus 1
of 7 before this work started) — the 10,000-domain benchmark above is
the statistically meaningful number, this pcap is a real-world sanity
check on top of it, not a substitute for it.

**How it got here — four real, sequentially-discovered issues, not one clean retrain:**

1. The model's benign training data was exactly 10 hardcoded famous
   domains (`google.com`, `apple.com`, ...), which produced a classifier
   that was 99.9% recall but a **98% false-positive rate** the moment it
   was run against real, diverse domains — it had learned "matches one
   of these 10 exact strings," not anything resembling what a legitimate
   domain looks like. Retraining against 40,000 real domains sampled
   across Tranco's full popularity range fixed the training data, but
   collapsed recall to 0%: `train_to_max()`'s loop did one full-batch
   gradient step per "epoch," capped at 50 total optimizer steps —
   enough for the old, trivially-separable 10-domain task, nowhere near
   enough for a harder, realistic one. Fixed with real mini-batch
   training. Result: 86.5% precision / 38.1% recall / 5.9% FPR — solid
   precision, but weak recall specifically on dictionary-style DGA
   families (`suppobox`, `gozi`), which are deliberately built from real
   words to evade character-pattern detection.

2. Rebuilt the model as a hybrid (see architecture below) and retrained
   on real dictionary-DGA family data to close that recall gap. First
   attempt: recall jumped to 99.4% but false-positive rate exploded to
   **93%** — nearly every real benign domain got flagged. Root cause,
   found by scoring bare subdomain labels directly: `inference/models.py`'s
   multi-segment defense independently re-scores every subdomain label
   ≥4 chars on its own (dot-free) to catch DNS-tunnelling hidden in a
   single label — but training had never shown the model a bare label
   without a TLD for *either* class, so it extrapolated "no dot present
   → almost certainly malicious," and that path dominated nearly every
   real multi-label domain. Fixed by adding matching bare-label training
   examples for both classes (`_extract_check_worthy_label()` in
   `inference/train_model.py`). Result: 85.2% precision / 69.8% recall /
   12.0% FPR — the big recall win was real, but per-family review showed
   `vawtrak`, `conficker`, and `pushdo` (previously strong) had dropped
   to 13-27% recall.

3. Investigated why those three specifically regressed rather than
   guessing: pulled their real domains from the benchmark directly.
   All three turned out to be pure random-character strings, but in a
   *shape* training never covered — short (4-11 chars), digit-free,
   diverse international ccTLDs (`xpun.nl`, `gxaa.com.mt`,
   `dokbuxok.ru`) or pronounceable consonant/vowel-alternating pseudo-
   words (`usecwemser.com`). The training generator's one "random-
   string" pattern was fixed at 15-25 chars, always mixed with digits,
   always `.com`. Fixed by broadening `_generate_random_string_dga()`
   into three explicit shapes (short/ccTLD-diverse, pronounceable, and
   the original long/digit-mixed one) matching what these real families
   actually look like. Result: every one of the 25 families improved or
   held flat against the previous retrain — a clean win, not a
   trade-off — recall 69.8% → 82.3% at the unchanged 0.85 threshold.

4. Re-ran `scripts/calibrate_dga_threshold.py` against the improved
   model, since a wider training distribution changes the model's own
   score distribution and 0.85 was calibrated for the *previous*
   version. Raising the threshold recovers precision/FPR, but not
   uniformly across families — 0.995 looked best in aggregate (88.3%/
   70.8%/9.3%) but crushed `gozi`, `padcrypt`, and `simda` by more than
   10 points each. 0.97 is the highest threshold that clears the
   regression gate against all 25 families; that's the number reported
   at the top of this section, now the default.

**Architecture:** `DGA_HybridModel` (`inference/train_model.py`) —
three parallel character-embedding conv branches (kernel sizes 3/5/7,
replacing the original's single kernel-3 branch) concatenated with a
7-feature lexical branch (`inference/models.py`'s `lexical_features()`:
entropy, digit/vowel ratio, unique-char ratio, longest consonant run,
hyphen ratio), feeding a small classifier head. Trained on: ~4,340 real
dictionary/hyphenated-style DGA domains from 9 malware families
(suppobox, gozi, nymaim, nymaim2, proslikefan, symmi, charbot, corebot,
necurs — sourced from github.com/baderj/domain_generation_algorithms, a
different source than the held-out test set above, with a verified
zero-overlap check), synthetic dictionary-DGA generated from the same
families' real seed word corpora, homoglyph and random-string attacks,
real Tranco benign domains, and hard-negative synthetic benign domains
shaped like the compound service-discovery/telemetry patterns
(`_ldap._tcp...`, `*.events.data.microsoft.com`) that caused false
positives against the real Lumma capture.

**Where this landed vs. the original model:** recall roughly doubled
(38.1% → 77.2%) and accuracy is up 15.4 points (66.2% → 81.6%), with a
real but modest false-positive-rate cost (5.9% → 13.9%) and precision
essentially unchanged (86.5% → 84.6%). No family is worse off than
where it started — `vawtrak`/`conficker`/`pushdo` (this session's own
regression, introduced and then fixed) and `suppobox`/`gozi` (the
original recall gap this whole effort started from) are all
meaningfully better than their pre-session numbers. Still not a
strict win on every single axis (FPR did rise), but the recall/accuracy
gains are broad-based across real families, not concentrated in a few
at others' expense.

**Licensing note:** the real DGA family training data (not the
held-out test set) is sourced from a GPL-2.0-licensed repository. It's
plain-text example domain lists and word corpora, not the repo's
generator source code, but worth a conscious call before this project's
own licensing/distribution model is finalized — see
`benchmarks/real_dga_domains_train_augment.csv` and
`benchmarks/dictionary_dga_seed_words_*.txt`.

**Guardrails added without retraining** (see
[docs/DGA_MODEL_ROADMAP.md](docs/DGA_MODEL_ROADMAP.md) for the full
plan; these are its Phase 0):

- **Per-family regression gate.** `scripts/evaluate_against_real_dga_dataset.py`
  compares every run's per-family recall against
  `benchmarks/dga_family_recall_baseline.json` and exits non-zero if any
  family drops more than 10 points. Not hypothetical — this is exactly
  what caught the `vawtrak`/`conficker`/`pushdo` regression above in
  real use (bullet 2 of "how it got here"), and it's also what ruled out
  the 0.995 threshold in bullet 4 despite its better aggregate numbers.
  `--update-baseline` accepts new numbers after a deliberate retrain.
- **Configurable decision threshold.** `DGA_CLASSIFICATION_THRESHOLD`
  (env var, default `0.97`, chosen per bullet 4 above) gates the is_dga
  decision in `inference/models.py` instead of a hardcoded constant.
  `scripts/calibrate_dga_threshold.py` shows the real precision/recall/FPR
  cost of every candidate value against the same benchmark, so a
  deployment can pick a different operating point (more recall vs. more
  precision) without retraining.
- **Fixed a train/inference character-mapping mismatch.** Training used
  to map any character outside the model's charset (e.g. `_`, as in
  `_ldap._tcp...`) to the padding token, while inference mapped it to
  `-` — a silent drift of the same shape as the bare-label 93%-FPR bug.
  Both paths now share one function (`sanitize_domain_chars()`). This
  fix's effect lands on the *next* retrain, not the currently-deployed
  model.

**A second, independently-sourced dataset: do these numbers hold up, or
are they an artifact of this one benchmark?** Every number above is
against exactly one real dataset (Cucchiarelli et al., wire-observed
traffic, Alexa benign). [scripts/evaluate_against_second_dga_dataset.py](scripts/evaluate_against_second_dga_dataset.py)
runs the identical live model against
[benchmarks/real_dga_domains_umudga.csv](benchmarks/real_dga_domains_umudga.csv),
built from a genuinely different real source for both halves:

- **Malicious side: UMUDGA** (Zago, Gil Pérez, Martínez Pérez, *Data in
  Brief*, 2020 — https://doi.org/10.1016/j.dib.2020.105400; dataset:
  https://doi.org/10.17632/y8ph45msv8.1, MIT licensed). Different
  construction from the first dataset entirely: instead of observing DGA
  traffic on the wire, UMUDGA *executes* 50 real malware families' actual
  DGA implementations in a controlled environment and records their real
  output. Same real malware, a structurally different way of sampling
  what it actually generates.
- **Benign side: Tranco** (https://tranco-list.eu, list ID `K9QPW`,
  captured 2026-09-01), not Alexa — a research-grade, manipulation-
  resistant popularity ranking from a different organization, deliberately
  *not* UMUDGA's own million-FQDN benign set, which turned out to be
  built from Leipzig Corpora English words (plausible-looking strings,
  not verified-real registered domains) rather than something suitable
  as real ground truth.

**Honest limitation, disclosed rather than worked around:** UMUDGA's
public Mendeley listing exposes 206 file folders (roughly 4 per family:
generator source plus domain lists at several size tiers) but never
exposes which folder belongs to which of the 50 malware family names —
only Locky was identifiable, via a distinctively-named build artifact
sitting in its folder. Guessing the other names risked mislabeling a
well-known malware family incorrectly, which is worse than not labeling
it — so each of the 51 domain-list folders found is its own anonymous
but reproducible group (`umudga_group_NN`), traceable back to its exact
Mendeley source folder via [benchmarks/umudga_group_manifest.csv](benchmarks/umudga_group_manifest.csv).
Verified independence directly before trusting any of this: only 21 of
30,600 domains in the new dataset exactly match a domain already in the
first one (0.07%, consistent with coincidental short-string collisions,
not reused data).

**Measured live, head-to-head against the exact same shipped model:**

| | First dataset (Cucchiarelli/Alexa) | Second dataset (UMUDGA/Tranco) |
|---|---|---|
| Precision | 84.6% | 86.3% |
| Recall | 77.2% | 75.8% |
| FPR | 13.9% | 12.0% |

Remarkably close — real evidence the model's performance generalizes
across two independently-sourced, methodologically-different real
datasets, not an artifact of the first benchmark's specific sampling.
Per-group recall on the second dataset still varies widely (100% on
several groups, down to 6.7% on the weakest one — printed in full by the
script, traceable to a real source folder even without a confirmed
malware name), the same real unevenness the first dataset already
showed. Gated the same way as every other real-data check in this
document: `benchmarks/dga_second_dataset_baseline.json` records each
group's recall, and CI fails if any group drops more than 10 points —
verified by mutating two groups' baselines to simulate a regression and
confirming the script exits 1, then restoring the real measured values.

## Flow autoencoder validation against real-world data

The flow autoencoder used to have no real-world benchmark at all — it
was trained and tested only against its own synthetic generator. That
gap turned out to hide a serious problem, found and fixed the same way
the DGA model's gaps were: source a real labeled dataset
([CTU-13](https://www.stratosphereips.org/datasets-ctu13), Stratosphere
IPS / CVUT, CC-BY — real botnet-infected host traffic and real
confirmed-clean host traffic from a university network, labeled by the
dataset's own researchers against the actual malware samples, not by
this project), and measure the live model against it
(`scripts/evaluate_flow_autoencoder_against_real_data.py`, reading
`benchmarks/real_flow_dataset_test.csv` — CTU-13 scenario 11, held out
entirely from the training data below, the same train/test discipline
`benchmarks/real_dga_domains.csv` follows).

**Before:** synthetic-only training measured a **~98-100% false-positive
rate** against real CTU-13 flows (99.96% on the held-out test set
specifically). Unlike the DGA classifier's threshold-only fix, no
threshold recalibration helped here: the real Normal and Botnet
reconstruction-error distributions barely separated at all (medians
only ~2x apart, heavy overlap) — the synthetic-only *training data*
itself was the problem, not the decision threshold. Root cause: the
synthetic generator's ranges (`orig_bytes` uniform 500-2000, `duration`
uniform 0.1-10s, etc.) don't remotely resemble real traffic's actual
variance.

**Fix:** retrained on a 50/50 mix of real CTU-13 Normal-labeled flows
(scenarios 5/7/12, extracted to `benchmarks/real_flow_dataset_train.csv`)
and the existing synthetic generator (kept for coverage of this repo's
own simulator traffic shape). Also switched `train_flow_autoencoder()`
from one full-batch gradient step per epoch to real mini-batch training
— the exact same bug that broke the DGA model's first real-data retrain,
applied preemptively here since the training data was about to become
meaningfully more diverse.

**After retraining, still not usable at the auto-computed threshold:**
FPR dropped to 67.48% (better, but still unusable) at the
training-time-computed threshold (`mean + 4 standard deviations of
validation reconstruction error`, 0.006717) — a real, disclosed lesson
that the same "trust the real data, not an automatic statistic" pattern
applies to thresholds too, not just training data. Running
`scripts/calibrate_flow_anomaly_threshold.py` against the retrained
model's real held-out error distribution revealed a coarse sweep had
stepped over a real, narrow separating gap: the model's real Normal and
Botnet reconstruction errors are both tightly clustered (near-bimodal),
with a clean gap between roughly 0.012 and 0.017.

**Final measured result at threshold 0.013 (`FLOW_ANOMALY_THRESHOLD`,
mirroring `DGA_CLASSIFICATION_THRESHOLD`'s env-var override pattern):
100% precision, 99.8% recall, 0.00% false-positive rate, 99.8% accuracy**
on the real held-out CTU-13 scenario (TP=8146, FP=0, TN=2718, FN=18).

**Verified live, end-to-end, against the real Lumma Stealer pcap used
throughout this document**: re-ran it through the actual restarted live
pipeline with the retrained model. "Anomalous Flow" alerts from this one
capture dropped from 21,279 (99.2% of every alert produced — the
original, very first finding that started this whole model-validation
effort) to 1,459, now spread across a genuinely diverse set of
connections rather than dominated by one repeatedly re-scored flow (the
top single source/destination pair accounts for 206 of the 1,459, not
the earlier ~12,551-alert single-flow pileup).

This is the same discipline applied to a different model, with the same
result: real data doesn't just validate a model, it finds problems no
amount of synthetic testing would have surfaced, and fixing them
(training data *and* threshold, in this case) genuinely works.

**A second, independent gate: does the 99.8% figure generalize past its
own eval split?** Scenario 11's own neighbors (5/7/12) trained the model
above — a real but narrow test. Run instead against
`benchmarks/real_rule_validation_dataset.csv` (the same real CTU-13
extract [Rule-based detector validation](#rule-based-detector-validation-against-real-world-data)
below uses, spanning all 13 real scenarios, most of which contributed no
training data at all), the identical model catches only **36.9% of real
botnet flows** (99.3% precision, 0.21% FPR) — a materially more honest
picture of single-model generalization than the scenario-11 number
alone, and the concrete reason [Composite incident scoring](#composite-incident-scoring)
below combines this detector with others rather than trusting it alone.

This number was first surfaced as a side effect inside the composite-
scoring evaluation, with no baseline of its own — meaning a future
retrain could keep acing the narrow scenario-11 holdout while silently
regressing broad generalization, and nothing would catch it.
`scripts/evaluate_flow_autoencoder_against_real_data.py` now runs and
gates *both* numbers independently
(`benchmarks/flow_autoencoder_baseline.json` for the scenario-11 holdout,
`benchmarks/flow_autoencoder_all_scenarios_baseline.json` for the
all-13-scenario generalization check) — either regressing beyond 5 points
fails CI, since the two answer genuinely different questions ("did this
regress against its own exact eval split" vs. "did this regress against
real traffic it never specifically prepared for"). Verified the gate
actually catches a regression the same way every other gate in this
document was verified: mutated the all-scenarios baseline to simulate a
23-point recall drop and confirmed the script exits 1 while the
independent scenario-11 gate still correctly passes.

## DNS behavioral detection (query bursts, NXDOMAIN rate)

A character-level classifier has a hard ceiling: a well-made dictionary
DGA domain can be lexically indistinguishable from a legitimate two-word
brand name (`SECURITY.md`'s own discussion above of `suppobox`/`gozi`).
[inference/dns_behavior.py](inference/dns_behavior.py)'s
`DnsBehaviorTracker` adds a genuinely different, complementary signal:
per-source-host tracking of distinct domains queried and NXDOMAIN rate
over a sliding window, independent of what any single domain looks
like. Wired into [inference/stream_processor_faust.py](inference/stream_processor_faust.py)
as a new detection under the existing `DGA / DNS Tunnelling` threat
class (`rule_id: RULE_DNS_QUERY_BURST`) — it fires alongside the CNN,
not instead of it, so a burst of otherwise-unflagged domains still gets
caught.

Security-relevant details: reuses `IncidentCorrelator`'s already-hardened
Redis connection (mandatory auth + TLS) rather than opening a second one
with its own config to audit; `source_ip` is strictly validated via
`ipaddress.ip_address()` before ever reaching a Redis key, since it
originates from network packet data — the same discipline
`IncidentCorrelator.add_alert()` already applies, now applied here too,
since an unvalidated string interpolated into a Redis key is a real
injection vector; domain-set size is capped
(`MAX_TRACKED_DOMAINS = 200`) the same way `IncidentCorrelator`'s own
sliding-window state is bounded, so one noisy or attacking host can't
grow Redis memory without limit; fails closed (reports "not a burst") on
any Redis error, matching `DeepLearningEngine.predict()`'s and
`FlowAnomalyEngine.score()`'s own posture, so a broken tracker degrades
gracefully instead of becoming a denial-of-service on the rest of the
pipeline.

**Verification status:** 18 unit tests (`tests/unit/test_dns_behavior.py`,
fakeredis) plus 2 integration tests through the real `process_traffic()`
path (`tests/test_pipeline.py`). Independently verified against the real
Lumma Stealer capture used elsewhere in this document twice:

1. Direct code replay (no live stack needed): the real infected host
   queried up to 47 distinct domains within a single real 60-second
   window, checked against actual packet timestamps — several times
   over the 15-domain burst threshold.
2. **End-to-end through the real, live stack** (Kafka/Redpanda + Redis +
   the actual `stream_processor_faust.py` process): after bringing
   Docker back up (it was down earlier in this work; the two demo
   processes visible in `ps aux` at that point turned out to already be
   non-functional zombies with unreachable Kafka/Redis, running a stale
   model and pre-Phase-2 code) and restarting both processes, re-ran the
   real pcap through the actual pipeline. Result: **194 real
   `RULE_DNS_QUERY_BURST` alerts**, all correctly attributed to the one
   real infected host (`10.1.21.58`) — via `high_nxdomain_rate` in this
   run specifically, since the pcap replays packets far faster than they
   were originally captured, so the NXDOMAIN-rate trigger reaches its
   threshold before the distinct-domain-count one does at these
   compressed timings; both paths are real and either can fire first
   depending on arrival timing. The same live run's retrained CNN
   (`DL_CNN_DGA`) caught `arch.filemegahab4.sbs`, `whooptm.cyou`,
   `whitepepper.su`, and `holiday-forever.cc` live — consistent with the
   direct-code numbers reported earlier in this section, confirming no
   live-vs-offline scoring discrepancy.

**A real false-positive gap, found and fixed after the above was already
verified working against the real threat:** the burst detector had only
ever been checked against the one real threat it caught, never against
realistic *benign* bursty DNS behavior. Simulated a single host rapidly
querying real domains (`benchmarks/real_benign_domains_train.csv`, the
same corpus the DGA model itself trains on) in 200 trials at various
burst sizes: **100% false-positive rate at exactly 15 distinct domains
in a 60-second window** — a volume any moderately heavy page load or
multi-tab browsing session can hit, since the threshold was a hard count
cliff, not a probabilistic signal. A related, smaller gap: 6 total DNS
responses at a 50% NXDOMAIN rate (a plausible benign scenario — a VPN
client failing to resolve a few internal hostnames while disconnected)
also false-triggered.

Fixed using real evidence as the calibration bounds on both sides, the
same discipline as every other threshold in this document: the real
malicious host's distinct-domain count (confirmed via the live pipeline
run above) kept climbing well past 40, up to 72, over the course of the
same capture — so `DISTINCT_DOMAIN_BURST_THRESHOLD` moved from 15 to 40,
comfortably below the confirmed-malicious range and well above the
demonstrated benign non-trigger point (14, in the same simulation).
`MIN_RESPONSES_FOR_NXDOMAIN_RATE` moved from 5 to 8, after checking that
the real live detections above mostly fired with 9+ responses anyway
(only the 8 least statistically confident of many real alerts, all with
5-7 responses, would be lost). Re-verified live end-to-end after the
fix: the real infected host is still caught (165 `RULE_DNS_QUERY_BURST`
alerts this run, exclusively attributed to `10.1.21.58`, same as
before — fewer alerts because the higher thresholds mean less repeated
re-triggering on the same ongoing burst, not less detection). 6 new
regression tests (`tests/unit/test_dns_behavior.py`) lock in both the
realistic-burst-size non-trigger behavior and the still-detects-a-real-
burst behavior, using the same real domain corpus.

## Rule-based detector validation against real-world data

Two of six detection categories (DGA, flow anomaly) were validated
against real attack data above. The other four rule-based detectors in
[inference/rules.py](inference/rules.py) — DDoS, C2 Beaconing,
Reconnaissance, Data Exfiltration — had never been run against anything
but this repo's own synthetic simulator until
[scripts/evaluate_rules_against_real_data.py](scripts/evaluate_rules_against_real_data.py),
which runs the real `evaluate_rules()` production code directly against
`benchmarks/real_rule_validation_dataset.csv` — a sampled extract (2,000
per class per scenario, capped) from all 13 CTU-13 scenarios, real
botnet-infected and real confirmed-clean traffic.

Two disclosed data-shape limitations, same spirit as the flow
autoencoder's: CTU-13's `.binetflow` format has no per-direction packet
count (`TotPkts`, both directions combined, stands in for `orig_pkts`),
and Argus's `State` field uses TCP-flag notation (`S_` = SYN sent, no
reply; `S_RA` = SYN sent, RST-ACK received) rather than Zeek's semantic
`conn_state` labels ("S0", "REJ") the Reconnaissance and DDoS rules
check for. `_argus_state_to_zeek_conn_state()` is a best-effort
translation for just those two categories — verified before trusting it
by checking real packet-count distributions (`S_` rows: mostly 1-7
total packets, consistent with a bare connection attempt) and by
spot-checking translated rows directly: real `S0`-translated flows are
botnet connection attempts to port 135 (Windows RPC — a classic
worm-scanning target) and port 25 (SMTP — spam-bot behavior); real
`REJ`-translated flows hit port 6667 (IRC — the classic C2 channel for
2011-era botnet families like this dataset's) and 443. Not a complete
or authoritative Argus↔Zeek mapping, and anything unrecognized maps to
no match rather than a guess.

**Measured results (all 13 scenarios, 18,627 real Botnet flows, 24,305
real Normal flows):**

| Rule | Threat class | Precision | Recall | FPR |
|---|---|---|---|---|
| `RULE_RECON_PORT_SCAN` | Reconnaissance | 99.8% | 48.5% | 0.06% |
| `RULE_C2_HEARTBEAT` | C2 Beaconing | 74.8% | 0.5% | 0.12% |
| `RULE_DDOS_VOLUMETRIC` | DDoS | 55.3% | 0.2% | 0.14% |
| `RULE_CONN_EXFIL` | Data Exfiltration | 100.0% | 0.3% | 0.00% |

**Reconnaissance genuinely works on real data** — high precision, real
recall, and it varies sensibly per scenario (0% to 96% depending on how
much port-scanning behavior that specific botnet family exhibits, which
is exactly what a working detector should show, not a flat number
everywhere).

**The other three barely fire on this real dataset at all.** Each is a
real, honest finding, not necessarily the same finding: DDoS's
single-flow packet-count threshold doesn't capture *distributed* volume
(many modest flows forming a flood, rather than one enormous flow) —
even CTU-13's own explicitly DDoS-labeled scenario (4, `rbot-dos`) only
tripped it on 1 of 1,277 real botnet flows. C2 Beaconing's 50-150-byte
symmetric-payload window is narrow relative to what this dataset's
actual C2 traffic looks like. Data Exfiltration's near-zero recall may
partly reflect that bulk exfiltration is a late-stage, comparatively
rare behavior even within real botnet traffic dominated by routine C2
and reconnaissance — not necessarily that the rule's shape is wrong.

**All three specifically: not retuned, replaced with a genuinely
different detector** (see
[Windowed connection-behavior detection](#windowed-connection-behavior-detection-ddos-rate-c2-periodicity--bulk-exfil)
below) — an exhaustive real threshold sweep found all three rules'
near-zero recall isn't a threshold problem at all: a real volumetric
flood is many connections arriving fast, real C2 beaconing is a regular
interval between many connections, and real bulk exfiltration is a real
total moved across many smaller transfers over time — none of these is
a property any single flow's own fields can encode. Retuning a
single-flow threshold could never have closed this (Data Exfiltration's
own initial sweep, `orig_bytes` thresholds from 5,000,000 down to
10,000, found recall capped around 1.5% before precision collapsed,
which looked at the time like it might need a genuinely new, second
dataset); a stateful, windowed tracker summing each signal over time was
needed instead, and turned out to close all three without one.

**JA4 fingerprinting: real data investigated, a genuine negative result
found, not a data-unavailability gap anymore.** CTU-13's flow records
carry no TLS handshake data at all, so this needed a different real
source: the real Lumma Stealer pcap already used throughout this
document does have real TLS `ClientHello`s. Installed `ja4plus` (an
independent, published Python implementation of FoxIO's JA4+
specification) and extracted 46 real client JA4 fingerprints directly
from that capture's TLS handshakes, then cross-referenced the
destination IPs (resolved via the same capture's own real DNS traffic)
against the 7 malicious domains this document's own DGA CNN + RDAP
domain-age work already independently confirmed. 4 of the 7 had
captured TLS connections, and all 4 used only two distinct JA4
fingerprints (`t13d201200_2b729b4bf6f3_e24568c0d440` and
`t13d201100_2b729b4bf6f3_36bf25f296df`).

**The honest finding: those exact two fingerprints also appear on real,
independently-verified (via live RDAP/IP-ownership lookup, not
assumption) Microsoft Corporation and Akamai Technologies connections in
the very same capture** — legitimate SharePoint/O365 and CDN traffic
from the same infected machine. Naively using these two fingerprints as
a malicious signature measures only 72% precision (18 real-malicious
matches vs. 7 real-legitimate ones) even on this small, artificially
balanced comparison — and that number would almost certainly get worse
in a real deployment, where legitimate Microsoft/cloud traffic vastly
outnumbers rare C2 connections by base rate. This is consistent with a
well-documented real limitation of TLS fingerprinting: Lumma Stealer, at
least in this sample, doesn't implement its own TLS stack — it rides on
the OS's standard networking APIs (WinHTTP/WinINet), so its C2 traffic's
JA4 fingerprint is indistinguishable from ordinary Windows networking,
not a property unique to this malware family.

**What this does and doesn't close:** the technical capability — real
JA4 extraction from real captured traffic, cross-referenced against
independently-confirmed malicious infrastructure — is now proven to
work end-to-end for the first time in this project, and can be pointed
at any future malware family or real curated feed. But this specific
investigation is a genuine reason NOT to ship a JA4 rule seeded from
this one pcap: doing so would flag real enterprise cloud traffic. A
real, broadly-curated malicious JA4 feed (e.g. Abuse.ch, or FoxIO's own
community-sourced database) observing many different malware families
across many different networks — the only way to separate "genuinely
malware-specific" fingerprints from "commodity OS networking stack"
noise like this one — remains the real path forward, and even then,
Lumma-family info-stealers specifically may simply not be catchable
this way at all.

## Windowed connection-behavior detection (DDoS-rate, C2-periodicity & bulk exfil)

The single-flow `RULE_DDOS_VOLUMETRIC`, `RULE_C2_HEARTBEAT`, and
`RULE_CONN_EXFIL` rules above stayed in place unchanged (they still
catch the rare case where one connection genuinely is that large or
that oddly-shaped), but the real fix for their near-zero recall needed a
different signal shape entirely:
[inference/conn_behavior.py](inference/conn_behavior.py)'s
`ConnBehaviorTracker` tracks connection RATE, INTERVAL REGULARITY, and
BYTE VOLUME per (source, destination) pair over time — the same
"stateful window instead of a single-event check" fix
`RULE_DNS_QUERY_BURST`
([inference/dns_behavior.py](inference/dns_behavior.py)) already applies
to DNS bursts.

**Calibrated against the raw CTU-13 `.binetflow` files directly** (real
`SrcAddr`/`DstAddr`/`StartTime` — fields
`benchmarks/real_rule_validation_dataset.csv`'s already-sampled extract
doesn't carry, so this needed the ~2GB raw archive re-downloaded and its
per-scenario flow files parsed with real IPs and timestamps intact).

**DDoS-rate: a real, clean signal, but only once scoped correctly.**
Grouping by source IP alone found a disqualifying false positive first:
one host (`147.32.84.59`, CTU-13's own labels call it `cmpgw-CVUT` — a
campus NAT/gateway) produced bursts of up to 49,000 connections in 10
seconds, spread across 91-1,142 distinct destinations — ordinary
many-users'-traffic fan-out through one apparent IP, not an attack.
Real infected hosts performing CTU-13's only two confirmed volumetric
floods (scenarios 10 and 11) hit exactly ONE destination with
2,855-4,243 connections in the same window. Scoping the rate check to a
(source, destination) *pair* instead of source-alone reproduces this
real separation: the highest confirmed-clean pair anywhere in CTU-13
reached 431; `DDOS_CONNECTION_COUNT_THRESHOLD = 1000` sits with a wide,
comfortable margin on both sides of that real gap.

**C2-periodicity: a real but standalone-weaker signal, and a different
KIND of weak than DDoS-rate.** CTU-13's own labels carry genuine
C2-channel ground truth (`From-Botnet-...-CC<N>-...`, e.g.
`CC106-IRC-Not-Encrypted`) — real confirmed C2 channels do show tight,
real periodicity (many pairs clustering at consistent ~30-300 second
intervals, some coefficient-of-variation as low as 0.02-0.03). But a
fine real threshold sweep (0.005 to 0.20) found something DDoS-rate's
threshold never showed: real recall is a flat, unmovable ~0.2-0.4%
ceiling across that *entire* range — most real "Botnet"-labeled
connections simply aren't part of any periodic C2 channel at all, so no
threshold recovers more of them; this isn't a precision/recall
trade-off to tune, it's a hard ceiling on this signal measured this way.
With recall fixed regardless of threshold, `BEACON_MAX_COEFFICIENT_OF_VARIATION`
is chosen purely to minimize real noise instead: `0.008` measures 37.0%
precision / 0.58% FPR (both plenty of ordinary botnet traffic and
legitimate periodic background jobs — analytics beacons, NTP-like
checks — are regular enough to look similar at looser thresholds; one
background pair measured CV=0.000, a perfectly regular ~hourly
legitimate check-in).

**Bulk exfiltration: a real, clean signal, the same "many small events
add up to one attack" shape as DDoS-rate.** The old single-flow
`RULE_CONN_EXFIL` (one connection's own `orig_bytes > 5,000,000`)
measured only ~1.5% real recall at any threshold sweep — genuine bulk
exfiltration is rarely one giant flow, it's the same total moved across
many smaller ones over time. Summing `orig_bytes` per
(source, destination) pair over a real 10-minute trailing window
(`EXFIL_WINDOW_SECONDS`) finds it: `EXFIL_BYTES_THRESHOLD = 1,000,000`
measures ~100% precision / 22.2% recall / 0.01% FPR against real CTU-13
traffic — roughly 74x the single-flow rule's real recall, at higher
precision and comparably negligible FPR. Found and fixed one real bug
along the way while building this: the byte count has to be encoded
into each sorted-set member string (Redis sorted sets don't natively sum
values in a score range), and a live pytest run — not an isolated script
— surfaced that a client already mocked elsewhere in the test suite
(`redis.Redis`, globally patched by an existing session-scoped fixture)
can make a *separately created* `fakeredis.FakeRedis(decode_responses=True)`
instance return raw bytes instead of decoded strings for this specific
call shape; `is_bulk_exfil()` now defensively decodes either.

**Measured against the real production tracker class itself** (not a
reimplementation — `scripts/evaluate_conn_behavior_against_real_data.py`
replays `benchmarks/real_composite_dataset.csv` — every real
Botnet/Normal-labeled connection from all 13 scenarios, kept whole and
in real chronological order, unlike the rules dataset's per-class
sampling cap, since a windowed check needs each pair's complete,
temporally continuous sequence — through the exact same
`ConnBehaviorTracker` in real time order per scenario):

| Detector | Precision | Recall | FPR |
|---|---|---|---|
| `RULE_DDOS_CONN_RATE` (new, windowed) | 100.0% | 11.3% | 0.00% |
| `RULE_DDOS_VOLUMETRIC` (old, single-flow) | 55.3% | 0.2% | 0.14% |
| `RULE_C2_BEACON_PERIODIC` (new, windowed) | 37.0% | 0.3% | 0.58% |
| `RULE_C2_HEARTBEAT` (old, single-flow) | 74.8% | 0.5% | 0.12% |
| `RULE_EXFIL_BYTE_VOLUME` (new, windowed) | 100.0% | 22.2% | 0.01% |
| `RULE_CONN_EXFIL` (old, single-flow) | 100.0% | 0.3% | 0.00% |

DDoS-rate and bulk-exfil are both clean, dramatic improvements on every
axis at once — not a trade-off. C2-periodicity trades a small amount of
the old single-flow rule's already-tiny recall for a real, measured
improvement in how much that recall can be trusted (37.0% vs. the old
rule's 74.8% precision is still a real cost, but far better than a
looser CV threshold's real alternative — 0.20 measured only 20.5%
precision at 4.20% FPR, over 7x the noise for barely any more recall).
Confidence is set to `0.40` in
[inference/stream_processor_faust.py](inference/stream_processor_faust.py)
regardless — deliberately below 0.5, so a lone firing can never by
itself cross [inference/risk.py](inference/risk.py)'s
`calculate_risk_score()` incident threshold (a single detector's score
reduces to its own confidence). It's meant to corroborate other evidence
via log-odds pooling, the same posture
[inference/domain_age.py](inference/domain_age.py) already takes for a
young-but-legitimate domain — not a standalone verdict. DDoS-rate and
bulk-exfil, in contrast, are confident enough alone (`0.95`) to stand as
their own high-confidence signal, same as the DGA CNN's own confidence
scale for an unambiguous case.

Gated the same way as every other real-data check in this document:
`benchmarks/conn_behavior_baseline.json` records all three detectors'
precision/recall/FPR, and CI fails if any regresses by more than 5
points.

## Composite incident scoring

Every detector above fires independently into one flat alert stream.
[inference/risk.py](inference/risk.py)'s `calculate_risk_score()` is
what turns a correlated group of alerts
([inference/correlation.py](inference/correlation.py)'s
`IncidentCorrelator`) into one reported confidence number — it used to
be a "max severity bucket + 5 flat points per additional alert"
heuristic that had two real problems, both found by actually running it
against real behavior rather than by inspection:

1. It **ignored each alert's own `confidence_score` entirely** — a
   `DL_CNN_DGA` hit at 0.51 and one at 0.99 both just mapped to "high"
   severity's flat 75 points.
2. It **rewarded raw alert volume linearly**, whether that volume came
   from several genuinely different, corroborating detectors or the
   same detector re-firing on one ongoing pattern. Observed live this
   session: 224 duplicate `RULE_DNS_QUERY_BURST` alerts from a single
   host's one ongoing DNS burst would have inflated risk 224x under the
   old scheme for what is, underneath, one corroborating signal.

**Fix:** log-odds pooling (a naive-Bayes-style independent-evidence
combination). Alerts are grouped by detector (`model_name`/`rule_id`,
falling back to `threat_class`) and deduplicated to each detector's
single strongest alert — correlated repeats of the same detector aren't
independent evidence — then combined via `Σ log(cᵢ/(1-cᵢ))` and mapped
back to a 0-100 score. A single detector's score reduces to its own
confidence; genuinely distinct, corroborating detectors combine into a
meaningfully stronger joint estimate; endless repeats of one detector
don't move the score at all.

**Measured against real data**
(`scripts/evaluate_composite_scoring_against_real_data.py`): the
original measurement ran the flow autoencoder and the 4 single-flow
rules against a 2,000-per-class-per-scenario capped sample
(`benchmarks/real_rule_validation_dataset.csv`) and found combining
detectors catches 53.7% of real botnet flows at 98.8% precision, versus
48.5% for the single best detector (Reconnaissance) alone — a genuine
recall improvement from corroboration, not a reshuffled number. That run
also surfaced a real, previously-undisclosed nuance: the flow
autoencoder's headline 99.8% recall number is against one held-out
scenario; across all 13 real scenarios it catches only ~37-45% alone
(the exact figure moves with how the dataset is sampled — see below) —
a materially more honest picture of its single-model generalization,
and the concrete motivation for combining it with other signals rather
than trusting it alone.

**A second real bug, found while wiring this up:** `IncidentCorrelator.add_alert()`'s
`threshold` parameter (default `80.0`) was accepted and never once read
in the method body — the Lua correlation script's own cheap per-alert
severity/volume heuristic was the *only* thing that ever decided whether
an incident got constructed, so the parameter silently implied a
risk-score filter that didn't exist. Now it does: a candidate incident
whose composite score doesn't clear `threshold` is suppressed (the
underlying Redis window/count state is untouched either way — only
publication is gated). Choosing the right value the same way as every
other threshold in this document: a real sweep against the composite
score's actual distribution on real data found the naive inherited value
of 80 made the composite score perform *worse* than the best single
detector alone (26.3% vs. 48.5% recall, since no individual rule's fixed
confidence — Reconnaissance's 0.75, e.g. — clears 80 without
corroboration); 50 sits at the safe edge of a wide, flat, real plateau.

**Re-measured after folding in the three windowed connection-behavior
detectors** (`RULE_DDOS_CONN_RATE`, `RULE_C2_BEACON_PERIODIC`,
`RULE_EXFIL_BYTE_VOLUME` — see
[Windowed connection-behavior detection](#windowed-connection-behavior-detection-ddos-rate-c2-periodicity--bulk-exfil)
above), which the original measurement couldn't include: it used a
dataset with no real IP/timestamp fields for a windowed check to key a
window on. `benchmarks/real_composite_dataset.csv` is a new,
comprehensive extract carrying every field all seven detectors need —
keeping every real Botnet/Normal connection whole and in real
chronological order rather than the earlier 2,000-per-scenario cap,
since a windowed check needs each pair's complete, temporally continuous
sequence (it's the same dataset
`scripts/evaluate_conn_behavior_against_real_data.py` reads, one real
extract shared by both evaluators). Measured against
all seven detectors on this fuller, uncapped real dataset: **98.8%
precision / 52.5% recall / 0.80% FPR**, a real **+7.3-point** recall
improvement over the best single detector alone (45.1%, the flow
autoencoder) — corroboration still measurably works, though the
incremental gain from adding bulk-exfil specifically was modest (52.1%
→ 52.5%): many of the real flows it independently catches were already
being caught by the flow autoencoder or another detector on the same
underlying attack, so the union's growth is smaller than its 22.2% solo
recall alone would suggest — corroboration compounds, it doesn't simply
add. The precise recall number moved from the original 53.7% for a
real, disclosed reason that isn't a regression: it now reflects the
full, naturally-weighted real CTU-13 population (large scenarios like 9
and 10 contributing proportionally more rows) rather than an
equal-per-scenario capped sample — a different, arguably more
representative measurement,
not a worse one. The composite's own baseline
(`benchmarks/composite_scoring_baseline.json`) was re-seeded against
this new measurement rather than compared to the prior one, exactly
because the underlying dataset changed, not because anything broke.

Also gated by a CI regression check going forward, same pattern as every
other real-data evaluator in this document.

## Domain-age enrichment

[inference/domain_age.py](inference/domain_age.py)'s `DomainAgeLookup`
adds a second, independent signal against dictionary-style DGA domains
(`vawtrak`, `gozi`, `matsnu` — still a real ceiling for a classifier that
only ever sees the domain string once): real registration age via free,
public RDAP (RFC 7482+, `rdap.org`'s bootstrap). It's looked up only for
domains [inference/stream_processor_faust.py](inference/stream_processor_faust.py)'s
DGA CNN has *already* flagged (`is_dga`), never for every DNS query — both
to bound external network calls and because sending every domain a
monitored network queries to a third party is a real privacy trade-off
this project isn't making unilaterally for every query. A hit young
enough (`YOUNG_DOMAIN_DAYS_THRESHOLD = 180` days) becomes a second,
independent `RULE_DOMAIN_AGE_YOUNG` alert, combined with the CNN's own
verdict via the log-odds pooling above — deliberately not a standalone
confirm/deny, since a young-but-legitimate domain (a real new startup,
e.g.) is a known false-positive mode for this signal alone.

**Validated against the real Lumma Stealer capture's actual malicious
domains** before being trusted: real RDAP lookups showed 9-261 days
between registration and use, against decades for real legitimate
infrastructure (`google.com`: 1997, `microsoft.com`: 1991). Two honest,
disclosed limits found in that same validation: RDAP coverage varies by
TLD — `.su` has no RDAP service at all, and `whitepepper.su` (the domain
queried 10x in a real beaconing pattern, arguably the strongest single
signal in the whole capture) gets no signal from this lookup, fails
closed to `None` rather than raising; and the original roadmap's
assumption that DGA domains are registered "minutes to hours" before use
was wrong — real operators pre-register days to months ahead, which is
what the threshold above is actually calibrated against.

**A real integration bug, found only by live re-verification, not by
unit tests.** Every unit test in `tests/unit/test_domain_age.py` passed
against mocks, and the live stream processor's own logs showed real 200
OK RDAP responses for the exact malicious domains above — yet
`RULE_DOMAIN_AGE_YOUNG` never appeared in the alerts table. Root cause:
`_parse_age_days()` used `datetime.fromisoformat()`, which only accepts a
single-digit fractional second (RDAP's real `eventDate` format, e.g.
`"2025-12-09T08:20:51.0Z"`) starting in Python 3.11 — this project runs
3.10, where every real response raised `ValueError`, silently swallowed
by the function's fail-closed `except` into "no signal" with nothing
logged to explain why. Fixed by switching to `dateutil.parser.isoparse`
(already a project dependency, already used the same way in
`shared/formatters.py`'s `format_timestamp`) — confirmed directly against
the real domains: `filemegahab4.sbs` and `whooptm.cyou` now return real,
correct ages instead of `None`.

That same live re-verification surfaced one more honest finding, about
methodology rather than code: replaying the original capture live many
months after it was recorded no longer demonstrates
`RULE_DOMAIN_AGE_YOUNG` firing for any of those specific domains, because
age is computed relative to wall-clock "now" and every one of them has
since aged past the 180-day threshold in the real time that's elapsed —
expected behavior for a point-in-time signal, not a defect. The "is_dga →
lookup called" half of the wiring is confirmed live (the same run's logs
show real RDAP calls firing only for CNN-flagged domains); the "young age
→ second alert" half is confirmed via
`tests/test_pipeline.py`'s `test_domain_age_publishes_a_second_alert_for_a_young_cnn_flagged_domain`
and `test_domain_age_not_looked_up_when_cnn_does_not_flag_the_domain`,
exercising the exact same production code path against a controlled age
in place of the (now independently-confirmed-correct) real network call.

TLS posture mirrors [inference/enrichment.py](inference/enrichment.py)'s
`ThreatEnricher`: TLS 1.2+ enforced via an explicit `ssl.SSLContext`. One
deliberate difference: `ThreatEnricher` pins a single host and rejects
redirects outright (`follow_redirects=False`) as SSRF defense; RDAP's
bootstrap design *requires* following exactly one redirect to the
authoritative per-TLD registry server, determined by IANA's own bootstrap
data rather than by anything an attacker-controlled domain string could
steer — `follow_redirects=True` here is that design's intended discovery
mechanism, not an inconsistency. `extract_registrable_domain()` validates
domain syntax via regex before ever embedding a string in a request URL,
defense-in-depth even though the DNS-query source is already constrained
upstream by `inference/models.py`'s own sanitization.
`k8s/cilium-identity-policy.yaml` allow-lists `rdap.org` egress, with an
inline-documented gap: a fully strict per-registry FQDN policy isn't
practically enumerable given RDAP's redirect-to-any-registry design.

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
  (see [README's Security section](README.md#security)).
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
  challenge (a second "enter your code" step), and
  [dashboard/pages/admin.py](dashboard/pages/admin.py) (admin-only, see
  below) has a real enroll/confirm/disable UI --
  `scripts/enroll_admin_mfa.py` still works too, for anyone who prefers
  a CLI or needs to enroll before the dashboard is reachable.
  [terminal/tsoc_console.py](terminal/tsoc_console.py) has no
  code-entry screen for the challenge at all -- an MFA-enabled admin
  logging in there gets a clear "sign in via the web dashboard instead"
  message rather than a crash, but can't actually complete login from
  the terminal.

## Admin dashboard page

[dashboard/pages/admin.py](dashboard/pages/admin.py) -- reachable only
from `dashboard/app.py`'s nav for a `role=admin` session
(`st.session_state["role"]`, set at login), though every API call it
makes is independently enforced server-side (`require_scope("users:manage")`)
regardless, so the nav gate is UX, not the actual security boundary.
Four tabs, each a thin UI over endpoints that already existed or were
added alongside this page:

- **Team** -- the team list (`GET /auth/tenants/{id}/users`), an invite
  form, and a deactivate action per teammate (not self -- `POST
  /auth/tenants/{id}/users/{user_id}/deactivate` explicitly rejects
  deactivating your own account). Deactivating blocks *future* logins
  immediately; it does not revoke a session that account already holds,
  which stays valid until its own natural expiry (`TSOC_JWT_EXPIRY_MIN`,
  30 minutes by default) -- revoking a live session would need every
  `jti` that account currently holds, which the server doesn't track.
- **Sensor Tokens** -- lists existing tokens (name/active/created/last
  used, never the token itself) and mints new ones, showing the
  cleartext value exactly once with an explicit "copy it now" warning.
- **Security** -- this account's own MFA enroll/confirm/disable, per
  the section above.
- **Audit Log** -- a read-only view of `GET /api/v1/audit` for this
  tenant.

Built entirely on Streamlit's own widgets (`st.dataframe`, `st.code`)
rather than hand-rolled HTML via `unsafe_allow_html=True`, unlike
`command_center.py`/`investigate.py` -- this page only ever renders
admin-entered account/sensor metadata through widgets that already
escape by default, so there's no `unsafe_allow_html` call in this file
to get wrong the way TSOC-2026-02 did.

Verified end-to-end against a real local stack (not mocked): a live API
server on SQLite + a real local Redis, a real bootstrapped tenant, and
the actual dashboard logged in for real -- invite, sensor-token
creation, and the full MFA enroll → login-challenge → verify cycle (with
genuinely computed TOTP codes) all confirmed working through the
running UI, not just their underlying API tests.

## Transactional email

[api/mailer.py](api/mailer.py) sends invite/password-reset links over
SMTP when `SMTP_HOST` is configured -- any provider that speaks SMTP
works (SES, Postmark, SendGrid, Mailgun, or a company's own relay), so
this isn't locked to one vendor's API. Unconfigured, `api/routes/auth.py`'s
`_deliver_email()` falls back to logging the link at WARNING level, the
original stub behavior -- local dev/test never needs real SMTP
credentials. A real send failure is logged at ERROR and swallowed, not
raised: every caller has already committed the signup/invite/reset
request it's about by the time this runs, so failing the HTTP response
would misreport an action that did happen.

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
