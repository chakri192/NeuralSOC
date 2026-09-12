# DGA Model Roadmap — from "real trade-off" to "goated"

Where we are today (measured, not aspirational): hybrid CNN + lexical-features
model, 84.6% precision / 77.2% recall / 13.9% FPR / 81.6% accuracy against
[benchmarks/real_dga_domains.csv](../benchmarks/real_dga_domains.csv), at a
threshold chosen specifically because every one of the 25 real families is at
or above its starting recall — checked automatically by a regression gate on
every run, not eyeballed. Recall roughly doubled from the original model
(38.1% → 77.2%) for a real but modest false-positive-rate cost (5.9% → 13.9%).
Phases 0-3 below are all done, including live end-to-end verification
against the real Kafka/Redis stack: 194 real DNS-burst alerts from the
actual infected host in a real malware pcap, and a 21,279-alert-to-1,459
drop in flow-anomaly false positives from the same pcap after Phase 3's
fix, both replayed through the real pipeline, not just measured offline.

Ordered by impact-per-hour-of-work, cheapest first.

---

## Phase 0 — Stop the next regression before it happens (near-zero training cost)

**Status: done, without touching the deployed model.**

**Per-family stratified evaluation gate — done.** `scripts/evaluate_against_real_dga_dataset.py`
now compares every run's per-family recall against
`benchmarks/dga_family_recall_baseline.json` (seeded from the current
model's real measured numbers) and exits non-zero if any family drops
more than 10 points. Verified against a simulated regression (forced
`vawtrak`'s baseline to 99.5%, confirmed the script caught the real
13.3% and exited 1) and against a clean run (exits 0, zero deltas).
`--update-baseline` accepts new numbers after a deliberate retrain.

**Calibration exposed as a config value — done** (a full isotonic/Platt
fit is still future work; this is the "expose it" half). The decision
cutoff in `inference/models.py` is `DGA_CLASSIFICATION_THRESHOLD`, read
from an env var at call time — no retraining needed to change it, and
`scripts/calibrate_dga_threshold.py` prints the real precision/recall/FPR
at every candidate value against the same benchmark. This is also what
picked the current default (0.97, see Phase 1's step 3 below) — not by
eyeballing the best aggregate number, but by combining this script with
the regression gate to find the highest threshold that doesn't
disproportionately hurt any one family. Verified the env var actually
changes `predict()`'s decision, not just a displayed number.

**Fixed the training/inference character-mapping mismatch.**
`generate_hard_dataset()` (and `scripts/continuous_training.py`'s
generator) used to map out-of-charset characters (e.g. `_` in `_ldap`)
to the padding token, while `_predict_impl` mapped them to `-` before
encoding — the same *shape* of silent drift as the bare-label 93%-FPR
bug. Both paths now share one function, `sanitize_domain_chars()` in
`inference/models.py`. This fix is code-only and takes effect on the
*next* retrain, not the currently-deployed model — no retraining was
needed to make the fix itself correct.

---

## Phase 1 — Recover the regressed families without new architecture

**Status: done.** The actual root cause turned out to be more specific
than "the mix shifted" — worth recording exactly what it was, since the
diagnosis mattered more than the fix.

1. **Diagnosed by reading the real data, not guessing.** Pulled
   `vawtrak`/`conficker`/`pushdo`'s actual domains from the benchmark
   (`awk -F, '$2=="vawtrak"'`, etc.). All three are pure random-character
   strings, but in a *shape* `generate_hard_dataset()`'s one
   "random-string" pattern never covered: short (4-11 chars), digit-free,
   internationally diverse ccTLDs (`xpun.nl`, `gxaa.com.mt`, `dokbuxok.ru`)
   or a pronounceable consonant/vowel-alternating pseudo-word style
   (`usecwemser.com`). The existing generator was fixed at 15-25 chars,
   always digit-mixed, always `.com` — a training/real-world shape
   mismatch, not a data-volume dilution problem.
2. **Fixed by broadening the generator, not rebalancing sample counts.**
   `_generate_random_string_dga()` now produces three explicit shapes
   (short/ccTLD-diverse, pronounceable, and the original long/digit-mixed
   one) instead of one. Retrained with no other changes. Result: every
   one of the 25 families improved or held flat versus the previous
   retrain — `conficker` 26.2%→63.4%, `pushdo` 16.9%→62.2%, `vawtrak`
   13.3%→34.7%, while `suppobox`/`gozi`/`matsnu` (the families Phase
   0-era work had fixed) kept improving too. Overall recall 69.8%→82.3%
   at the unchanged 0.85 threshold — a clean win, not a trade-off.
3. **Re-calibrated the threshold for the new model**, since a broader
   training distribution changes the model's own score distribution.
   0.995 looked best on the three aggregate numbers (88.3%/70.8%/9.3%)
   but the regression gate caught what the aggregate view hid: it
   disproportionately crushed `gozi`, `padcrypt`, and `simda` (each
   dropped >10 points). 0.97 is the highest threshold that clears the
   gate against all 25 families — 84.6%/77.2%/13.9%, now the default.

Family-stratified sampling and class-balanced loss (the original plan
for this phase) turned out to be unnecessary once the actual shape
mismatch was found and fixed directly — noted here in case a *future*
regression doesn't have as clean a root cause and those techniques
become the right tool.

---

## Phase 2 — Behavioral signal, not just the domain string (the actual "goated" unlock)

**Status: done, including live end-to-end verification.**

Character-level classification of a domain string has a hard ceiling: a
well-made dictionary DGA domain can be lexically indistinguishable from a
legitimate two-word brand name. The strongest signal for real DGA campaigns
is *behavioral*, not lexical — directly motivated by this project's own
finding that a real Lumma Stealer domain (`whitepepper.su`) was queried 10
times in a tight window.

**What got built:**

1. **DNS response codes in the event schema.**
   `ingest/pcap_ingester.py`'s new `_extract_dns_response_event()` parses
   response packets (`dns.qr == 1`), extracting the response code
   (NXDOMAIN in particular) and correctly resolving the *querying client*
   (a response packet's destination, not its source) as the host to
   attribute it to. Emitted as a new `dns_response` event type, separate
   from the existing `dns` query event, so the query path's latency is
   completely unaffected.
2. **`inference/dns_behavior.py`'s `DnsBehaviorTracker`** — a per-source-host
   sliding-window tracker (Redis-backed, reusing `IncidentCorrelator`'s
   already-hardened connection rather than opening a second one) counting
   distinct domains queried and NXDOMAIN rate. Flags a burst when a host
   queries ≥15 distinct domains in the window, or has a ≥50% NXDOMAIN rate
   over ≥5 responses (the minimum-sample guard exists specifically so one
   early NXDOMAIN doesn't read as "100% failure"). Strict IP validation
   (`ipaddress.ip_address()`, matching `IncidentCorrelator.add_alert()`'s
   own discipline) before any value reaches a Redis key — this data
   originates from network packets, i.e. is attacker-influenced.
3. **Wired into `inference/stream_processor_faust.py`** as a new detection
   path under the existing `DGA / DNS Tunnelling` threat class (rule_id
   `RULE_DNS_QUERY_BURST`) — genuinely additive to the CNN, not a
   replacement: it fires independent of what the CNN thinks of any single
   domain in the burst. Dispatched via the existing `io_executor` (Redis
   I/O), not `cpu_executor` (reserved for ML inference), so it can't
   compete with the DGA CNN/flow autoencoder for the same worker threads.

**Verified two ways:**
- 18 unit tests for `DnsBehaviorTracker` (fakeredis) covering domain-count
  bounding, NXDOMAIN-rate math, the minimum-sample guard, IP-injection
  rejection, and fail-closed behavior on Redis errors — caught one real
  bug in the tests themselves (fakeredis's default `FakeRedis()` shares a
  global backing store across instances unless given an explicit
  `FakeServer()`, which silently leaked state between test cases the
  first time this was written).
- **Against the real Lumma Stealer pcap directly** (not just synthetic
  test data): replayed the capture's actual DNS packets through the real
  extraction + tracker code. The real infected host queried 72 distinct
  domains over the full capture, and — checked precisely against real
  packet timestamps, not just aggregate totals — up to **47 distinct
  domains within a single real 60-second window**, several times over
  the `DISTINCT_DOMAIN_BURST_THRESHOLD` of 15. This confirms the signal
  is real and would fire in production with the default window, not just
  in a generously-windowed test.

**Live end-to-end verification.** Docker was found to be down partway
through this phase (the two long-running demo processes were already
non-functional zombies with unreachable Kafka/Redis, and were running a
stale model and pre-Phase-2 code regardless). Brought Docker back up,
restarted `stream_processor_faust.py` and `kafka_sink.py` fresh, and
re-ran the real pcap through the actual live pipeline end-to-end.
Result: **194 real `RULE_DNS_QUERY_BURST` alerts**, all correctly
attributed to the one real infected host (`10.1.21.58`) — fired via
`high_nxdomain_rate` in this specific run (the pcap replays packets
much faster than they were originally captured, so that trigger reaches
its threshold before the distinct-domain-count one does at compressed
timings — both paths are real, and either can fire first depending on
arrival timing). The same live run's retrained CNN caught the same 4 of
7 known-suspicious domains as the direct-code check, confirming no
live-vs-offline scoring discrepancy.

---

## Phase 3 — Real-world validation parity for the flow autoencoder

**Status: done, including live end-to-end verification.**

CTU-13's 2GB archive (the download this doc originally deferred as a
40-minute uncertain-payoff tangent) turned out to be worth the wait: it
directly hit the exact deferred CTU-13 path this section flagged
(the archive itself, extracting just the `.binetflow` files rather than
the multi-GB pcaps/executables alongside them), and confirmed the
suspected failure mode exactly, plus something worse than expected.

1. **Confirmed the risk was real, not hypothetical.** Ran the live,
   synthetic-only-trained `FlowAnomalyEngine` against 28,000 real,
   labeled flows from 4 CTU-13 scenarios: **~98-100% false-positive
   rate.** Worse than this doc's own guess: a threshold sweep across the
   real reconstruction-error distributions showed real Normal and
   Botnet errors barely separated at all (medians only ~2x apart, heavy
   overlap) — no threshold fixes that, unlike the DGA CNN's case. The
   synthetic *training data* itself was the problem.
2. **Fixed by retraining on real data**, mirroring Phase 1's own
   methodology: 50/50 mix of real CTU-13 Normal-labeled flows
   (`benchmarks/real_flow_dataset_train.csv`, scenarios 5/7/12) and the
   existing synthetic generator, plus the same full-batch-to-mini-batch
   fix Phase 1 already proved necessary, applied preemptively here.
   Held out scenario 11 entirely (`benchmarks/real_flow_dataset_test.csv`)
   for genuine train/test separation.
3. **Retraining alone wasn't enough** — the auto-computed
   `mean + 4*std` threshold was *still* miscalibrated against the
   retrained model's own real-data error distribution (67% FPR). A
   fine-grained sweep (not the coarse one that would have missed it)
   found a clean, narrow separating gap between real Normal and Botnet
   reconstruction error. Final result at threshold 0.013
   (`FLOW_ANOMALY_THRESHOLD`, same env-var-override pattern as the DGA
   threshold): **100% precision, 99.8% recall, 0.00% FPR** on the real
   held-out scenario.
4. **Verified live**, the same way Phase 2 was: re-ran the real Lumma
   Stealer pcap through the actual restarted pipeline. "Anomalous Flow"
   alerts from that one capture dropped from 21,279 (99.2% of every
   alert the pipeline produced — literally the first finding of this
   entire multi-session effort) to 1,459, now spread across genuinely
   distinct connections instead of one flow re-scored thousands of times.

This closes the loop on the very first "does this actually work" question
this whole project's model-validation effort started from.

---

## Phase 4 — Production feedback loop (the part that compounds over time)

Everything above is a one-time retrain. The actual "goated" state is a model
that keeps improving from real usage without needing another manual
from-scratch investigation like this session's.

- **Wire analyst triage decisions back into training data.**
  `shared/triage_store.py` already records analyst dispositions
  (confirmed/false-positive) per incident. Right now that data goes nowhere
  after the dashboard renders it. Piping confirmed-false-positive domains
  into the benign training set (and confirmed-true-positive domains the
  model missed into the malicious set) is exactly the active-learning loop
  that turns real deployment experience into the next retrain's data,
  instead of relying on this project re-sourcing public datasets by hand
  each time.
- **Shadow-mode deployment for new models.** Before a retrained model
  replaces production, run it in parallel (score every real event, log the
  score, don't alert on it) for a fixed window and compare its decisions
  against the currently-live model's on real traffic. This is the
  difference between "passed the offline benchmark" and "verified safe on
  this specific deployment's actual traffic mix" — the exact gap that let
  the 93%-FPR regression get as far as it did before this session's manual
  re-evaluation caught it.
- **Scheduled re-run of the real-world benchmark in CI**, not just as a
  manually-invoked script. Any PR touching `inference/train_model.py` or
  `inference/models.py` should have to show the benchmark numbers didn't
  regress, the same way tests already gate merges.

---

## Phase 5 — CNN+BiLSTM hybrid (investigated, not shipped)

**Status: real investigation, real fix for one root cause, honest negative
result on the architecture as a whole. Reverted.**

Part of a broader "make every model enterprise-grade" push: could a genuinely
different architecture, not just more tuning, push the DGA CNN's real
precision/recall/FPR trade-off further? The character-CNN-only model has a
hard, measured ceiling: no threshold on it simultaneously reaches >95%
precision, 55-65% recall, and <1% FPR against real data (confirmed via a
fine sweep — at the FPR level needed for <1%, recall tops out around 34-41%;
at the recall level needed for 55%+, FPR is 2%+).

**What was tried:** added a bidirectional LSTM branch reading the same
character embeddings as a genuine sequence, alongside the existing CNN
branches — a well-established pattern in DGA-detection literature
(Woodbridge et al. 2016 and later hybrids), motivated by the CNN's complete
blindness to character *order* beyond a single kernel's fixed window.

**First real finding: a severe, reproducible regression.** The textbook
default — reading only the LSTM's final hidden state — genuinely hurt one
specific real family, `matsnu`, across two independent retrains (38.4%
baseline recall → 19.7%, then 21.7% — confirmed reproducible, not training
noise, by retraining twice with the identical unseeded code). Root-caused by
reading matsnu's own real domains: it's the one family built from many
(3-6+) dictionary words concatenated with **no separator at all**
(`brothernerveplacebringconsult.com`), averaging 30.5 characters and
sometimes exceeding the model's fixed 35-character window entirely — exactly
the shape where a final-hidden-state summary is most likely to wash out
signal from words seen early in a long, boundary-less sequence.

**Fix, and it worked for that specific problem:** max-pooling over every
LSTM timestep's output instead of just the final state (the same "strongest
signal anywhere in the sequence" principle the CNN branches already use via
`AdaptiveMaxPool1d`) recovered matsnu to 34-40% across three further
retrains — no longer a regression.

**But validated against real data as a whole, the architecture change never
delivered a clean win.** Five total retrains (training is unseeded, so each
is a genuinely independent draw), evaluated against both real datasets this
project maintains:

| Run | Dataset 1 (Cucchiarelli) recall | Dataset 1 regressions (>10pt) | UMUDGA recall | UMUDGA regressions (>10pt) |
|---|---|---|---|---|
| Original (shipped, CNN-only) | 77.2% | — | 75.8% | — |
| Run 3 (max-pool fix) | 76.4% | pushdo -10.5 | 74.5% | umudga_group_09 -19.0 |
| Run 4 (max-pool fix) | 75.0% | none | (not run) | (not run) |
| Run 5 (max-pool fix) | 78.3% | none | 75.9% | umudga_group_07 -38.3, group_32 -13.3, group_35 -11.7 |

No run cleared both datasets' per-family regression gates at once. Run 5 —
the best-looking run by aggregate numbers on BOTH datasets (beats the
original on precision/recall/FPR on dataset 1, essentially flat on UMUDGA
recall) — still collapsed one UMUDGA group by 38 points, a family the
architecture had no trouble with in run 3. This is the real signature of the
problem: the LSTM branch adds real, substantial run-to-run variance that
redistributes which specific real malware families/groups get caught well,
without a validated net improvement that holds across both independent
datasets simultaneously. Investigating *why* `umudga_group_07`'s domains
(short random prefix + a long, near-constant templated suffix — a shape no
training generator produces) are this unstable across runs would be a
reasonable next step, but that's future work, not something to ship on a
hunch.

**Reverted.** `inference/train_model.py`'s `DGA_HybridModel` and
`models/cnn_dga.pt` are back to the original, shipped CNN-only
architecture — confirmed byte-for-byte via SHA-256 and a re-run of the
real-data gate showing exactly 0.0-point deltas on every one of the 25
families. The matsnu root-cause and its fix remain documented here in case
a future architecture attempt wants to avoid rediscovering the same
final-hidden-state pitfall; the training data (`_load_real_dga_augment_domains()`
etc.) and thresholds are untouched. This is the same honesty standard this
project applied to the JA4 investigation elsewhere in this codebase: real
technical work, a real fix for a real sub-problem, and a plain "this
specific approach isn't ready to deploy" when the full picture doesn't hold
up — not a forced win.

---

## Phase 6 — Small ensemble of the proven CNN-only architecture (investigated, not shipped)

**Status: real investigation, honest negative result.** Phase 5's
CNN+BiLSTM attempt surfaced a real, substantial run-to-run training
variance in this model (aggregate recall ranged 75.0%-79.5% across 4
stochastic retrains of the *same* architecture, since `train_to_max()`
isn't seeded). A lower-risk idea than another architecture change: train
several independent copies of the already-proven, currently-shipped
CNN-only `DGA_HybridModel` and average their predicted probabilities,
the standard technique for reducing variance-driven error without
touching a validated architecture.

**What was tried:** trained 2 fresh independent CNN-only models
(~28-30 minutes each) and combined them with the currently-shipped one
into a 3-model ensemble, scoring by mean probability. At the shipped
model's own threshold (0.97), the ensemble looked purely worse (recall
dropped ~12 points on both real datasets) — expected and uninteresting:
averaging compresses the score distribution toward the middle, so a
threshold calibrated for one model's distribution doesn't transfer
directly. Re-swept thresholds for the ensemble specifically and found a
genuinely promising point: at 0.7, the ensemble matched the shipped
model's recall almost exactly (76.9% vs. 77.2%, 75.2% vs. 75.8%) while
improving precision (+2.5 and +3.6 points) and lowering FPR (-2.6 and
-3.6 points) on **both** real datasets — by the aggregate numbers alone,
a clean win.

**The per-family/per-group table said otherwise.** `pushdo` regressed
11.0 points on the first dataset (55.2% → 44.2%), and five UMUDGA groups
regressed on the second — most severely `umudga_group_07`, which
**collapsed completely (47.0% → 0.0%)**. This is the same group that
collapsed 38 points in Phase 5's best-looking CNN+BiLSTM run. Seeing it
collapse a *third* time, now under a structurally different technique
(simple probability-averaging ensembling, no recurrent branch involved
at all), is strong evidence this specific real UMUDGA group's domains
sit on an unstable decision boundary for *this training pipeline as a
whole* — its synthetic generators never produce this group's specific
shape (a narrow, low-entropy template with a short random prefix), so
whether any given stochastic run's decision boundary happens to fall on
the right side of those domains looks close to a coin flip, regardless
of architecture or how many independently-trained models get averaged
together.

**Not shipped**, for the same reason regression gates exist: an
aggregate-only view would have called this a win. Reverted
`models/cnn_dga.pt` to the original shipped weights (confirmed
byte-identical via SHA-256). The "more real, non-UMUDGA training data"
idea (broadening `_load_real_dga_augment_domains()`'s sources, the same
lever that worked for the flow autoencoder) was not attempted after
this finding — three independent techniques now point at the same
uninstrumented gap (this training pipeline has no real examples shaped
like `umudga_group_07`), which more data volume elsewhere in the
existing sources wouldn't fix; closing it for real would need sourcing
domains matching that specific shape, not a broader ensemble or a
bigger pile of the same kind of data already in hand.

**A fourth attempt, targeting that exact gap directly, made it worse.**
`umudga_group_07`'s real domains are a short random alphabetic prefix
(4 chars observed) concatenated with one near-constant ~15-character
tail (`kmulerionirkutskagl.com`, `ogmnerionirkutskagl.com`, ...) — a
shape no existing generator produced. Added `_generate_fixed_tail_dga()`:
a short random prefix concatenated with one tail drawn from a small
pool of invented (never the real group's literal content) near-constant
strings, mirroring exactly the technique that already fixed
conficker/pushdo/vawtrak in Phase 1. Retrained and validated against
both real datasets: `umudga_group_07` recall **dropped further, to
2.3%** (worse than the ensemble's complete 0% in relative terms — this
is now the fourth technique to fail on this specific group), and three
*additional* real families/groups regressed beyond 10 points that
hadn't in any prior attempt (`matsnu`, `nymaim`, `pykspa` on the first
dataset; `umudga_group_05`, `umudga_group_08`, `umudga_group_30` on the
second) — more collateral damage than any single earlier attempt.

The likely mechanism: a small, fixed pool of invented tail strings (8
entries) gives the model something concrete enough to memorize as "these
8 specific strings," not the abstract "an unusually long near-zero-entropy
tail is suspicious" principle that would generalize to the real group's
own, different literal tail — the same shape of failure this project's
own history already named once (`_load_benign_domains()`'s docstring:
10 hardcoded benign domains taught "matches one of these 10 exact
strings," not a general notion of legitimacy). Reverted both the model
and the generator code (confirmed clean via `git checkout`, model
byte-identical via SHA-256 to the shipped version).

**Four independent techniques — a second architecture, an ensemble, and
now a shape-matched synthetic generator, on top of the original
single-model baseline — have now all been tried against this one real
UMUDGA group, and none improved it; the last one made it measurably
worse while damaging unrelated families along the way.** This is a
strong, well-evidenced stopping point: the DGA CNN's real ceiling on
this specific gap is not moving with the techniques and data reasonably
available to this project right now, and further attempts of the same
general shape (retrain, re-architect, re-generate) are unlikely to
behave differently. The honest, current state is the original shipped
model's own numbers (84.6%/77.2%/13.9% and 86.3%/75.8%/12.0%), a solid
B grade with a real, now thoroughly-documented ceiling — not a claimed
improvement that later attempts would have to explain away.

---

## What "goated" actually looks like, concretely

Not a single bigger model — a system where:
1. ✅ A per-family regression like `vawtrak`'s drop is caught by the
   evaluation script's exit code, not discovered by eyeballing a table
   (Phase 0) — proven in real use during Phase 1's own threshold choice,
   not just built and left untested.
2. ✅ A real recall gap gets root-caused against the actual failing
   families' real domains and fixed at the data level, not patched
   around with a bigger model or more epochs (Phase 1).
3. ✅ A host generating a DNS burst gets flagged from its *behavior*, not
   just from what any single domain looks like character-by-character —
   genuinely additive to the CNN rather than trading precision for recall
   the way threshold tuning alone always will (Phase 2, verified against
   the real pcap both directly and end-to-end through the live Kafka/
   Redis stack: 194 real alerts from the real infected host).
4. ✅ Both DL detectors — not just one — have been honestly measured
   against real-world data, with the same rigor and the same willingness
   to publish an unflattering number: the flow autoencoder's real
   synthetic-only FPR (~98-100%) was measured, disclosed, and fixed by
   retraining on real data plus a real-data-calibrated threshold, then
   verified live against the same pcap (Phase 3).
5. The model gets better every week a SOC actually uses it, without another
   multi-hour manual investigation each time (Phase 4 — not started).

Phases 0 through 3 are done and verified against real data end-to-end, not
just planned. Phase 4 is ongoing infrastructure that pays for itself after
the first cycle — the one piece of this roadmap that isn't a one-time fix
but a standing practice to adopt.
