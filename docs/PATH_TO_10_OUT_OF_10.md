# Path to 10/10

Honest starting point, not a sales pitch: two of six detection categories
(DGA, flow anomaly) are now validated against real attack data and hold up
well. Of the other four, three now have real numbers too — one
(Reconnaissance) genuinely works, three others (DDoS, C2, Exfil) barely
fire on real traffic. Every detector fires independently into one flat
alert stream — nothing combines their signals into one calibrated
per-incident confidence. And every validated model/rule so far is proven
against exactly one real dataset, not several. That's the gap between
"genuinely good, evidence-backed in places" (where this is today) and 10/10.

Ordered by how directly each phase closes a *named* gap from the honest
assessment above, cheapest first. CTU-13 (already downloaded, CC-BY,
[docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md) has the full citation)
covers most of Phases 5-6 with zero new data-sourcing — a deliberate
choice: reuse what's already been paid for in download time before going
back to the well for a new dataset.

**Phases 5, 6, and 7 are done** (6 partially — JA4 still needs new data).
5 and 6 found real, previously-unmeasured gaps, not false alarms: Phase
5's DNS burst detector had a 100%-reproducible false-positive bug; Phase
6 found that only 1 of 4 newly-validated rules actually works well
against real attack traffic. Phase 7 makes sure neither regresses
silently: every validated detector (DGA, flow anomaly, and the 4 rules)
now has the same CI-enforced real-world regression gate. See each phase
below for the numbers.

---

## Phase 5 — Close the DNS-behavior false-positive blind spot

**Status: done.** The suspected gap was real, and worse than "plausible":
200/200 simulated trials of a single host querying just 15 real domains
(`benchmarks/real_benign_domains_train.csv`) in a 60-second window
**false-positived 100% of the time** — the threshold was a hard count
cliff, not a probabilistic signal, and 15 is a volume any moderately
heavy page load or multi-tab session routinely exceeds. A related gap:
6 total DNS responses at a 50% NXDOMAIN rate (a plausible benign VPN-
disconnect scenario) also false-triggered.

Fixed using real evidence on both sides of the calibration, not a guess:
the real Lumma Stealer host's distinct-domain count (from Phase 2's own
live verification) kept climbing past 40 up to 72 over the same capture,
so `DISTINCT_DOMAIN_BURST_THRESHOLD` moved from 15 to 40 — comfortably
below the confirmed-malicious range, well above the demonstrated benign
non-trigger point. `MIN_RESPONSES_FOR_NXDOMAIN_RATE` moved from 5 to 8
after confirming the real live detections mostly fired with 9+ responses
regardless (only the least statistically confident early alerts, at 5-7
responses, would be lost). Re-verified live end-to-end after the fix:
the real infected host is still caught (165 alerts this run vs. 224
before — fewer because of less repeated re-triggering on the same
ongoing burst, not less detection). 6 new regression tests lock in both
behaviors using the same real domain corpus this was found with.

See [SECURITY.md](../SECURITY.md#dns-behavioral-detection-query-bursts-nxdomain-rate)
for the full writeup.

## Phase 6 — Real-world validation for the other 4 detection categories

**Status: done for 3 of 4; JA4 remains genuinely blocked on new data.**

Ran `scripts/evaluate_rules_against_real_data.py` (the real
`evaluate_rules()` production code, not a reimplementation) against
`benchmarks/real_rule_validation_dataset.csv` — a sampled extract from
all 13 CTU-13 scenarios (18,627 real Botnet flows, 24,305 real Normal
flows), closing DDoS, C2 Beaconing, Reconnaissance, and Data
Exfiltration with zero new data-sourcing, exactly as predicted below.

**Result: one real win, three real gaps.**
`RULE_RECON_PORT_SCAN` genuinely works — 99.8% precision, 48.5% recall,
varying sensibly per scenario (0-96%) with how scan-heavy each real
botnet family actually is. `RULE_DDOS_VOLUMETRIC`, `RULE_C2_HEARTBEAT`,
and `RULE_CONN_EXFIL` barely fire on real traffic at all (0.2-0.5%
recall each) — three distinct real reasons, not one bug: DDoS's
single-flow threshold misses *distributed* volume (many modest flows,
not one huge one — even the dataset's own explicitly-DDoS-labeled
scenario only tripped it once), C2's byte window is narrower than this
dataset's actual beacon traffic, and Exfil's near-zero recall may partly
reflect that bulk exfiltration is genuinely rare even within real
botnet traffic dominated by C2/recon. Full numbers and the Argus-state
translation this needed (with its own empirical verification) are in
[SECURITY.md](../SECURITY.md#rule-based-detector-validation-against-real-world-data).

**Deliberately not retuned.** Unlike the DGA/flow-model fixes, these
three rules have no held-out real test set to validate a "fix" against
— adjusting thresholds using only the same data that measured the gap
would be circular, and would compound the single-dataset risk Phase 10
already names. Recorded as a disclosed limitation, not silently patched.
If this gets picked up: source a *second* independent real dataset first
(Phase 10), then tune against one and validate against the other, the
same held-out discipline the DGA benchmark already uses.

**JA4 fingerprinting is still blocked on new data sourcing** — CTU-13's
flow records carry no TLS handshake data at all. Needs a real malicious
JA3/JA4 fingerprint feed (Abuse.ch's SSLBL/ThreatFox) cross-referenced
against JA4s extracted from a real malware pcap. Confirm Abuse.ch's
terms permit this use before starting, the same diligence already
applied to CTU-13/baderj's repo.

## Phase 7 — CI gate parity

**Status: done.** Every validated detector now has the same protection
the DGA model already did. Added `--update-baseline`/regression-check
logic (mirroring the DGA gate exactly) to both
`scripts/evaluate_flow_autoencoder_against_real_data.py` and
`scripts/evaluate_rules_against_real_data.py`, wrote the current real
numbers as `benchmarks/flow_autoencoder_baseline.json` and
`benchmarks/rule_validation_baseline.json`, and added both as CI steps
in `.github/workflows/ci.yml`. Verified both gates the same way the DGA
one was verified originally: pass cleanly against themselves, and
correctly fail (exit 1) on a simulated regression — the flow gate
against a mocked 0%-recall model, the rules gate against a mocked
Reconnaissance rule that stops firing.

Worth being explicit about what this gate does and doesn't claim for the
three weak rules (DDoS, C2, Exfil): it protects today's real, already-
weak baseline from getting *worse* without anyone noticing — it is not a
claim that 0.2-0.5% recall is acceptable. Fixing those is a separate,
deliberate decision (Phase 6's own note on why they weren't retuned
yet), not something this gate makes for you.

## Phase 8 — Composite, per-incident scoring instead of independent alerts

Right now the DGA CNN, the entropy rule, the DNS-burst tracker, and the
flow autoencoder each fire independently — a single suspicious connection
can produce two, three, or more separate alerts for the same underlying
incident (already visible in this session's own live-pipeline runs: DGA
alerts and burst alerts both firing for the same domain query).
`inference/correlation.py` already groups alerts into incidents by
source/time window, but doesn't combine their *confidence* into one
calibrated number — an incident with one weak signal and one with four
weak signals corroborating each other currently look similar in severity.

A genuinely 10/10 system computes one incident-level risk score as a
function of which detectors fired and how confidently, calibrated against
labeled ground truth (CTU-13's rich per-flow labels are, again, directly
reusable here as training/validation data for this calibration) rather
than each detector's threshold being tuned in isolation. This is the
piece that actually delivers the "recall and precision improve together"
promise from the original roadmap's Phase 2 framing — behavioral and
lexical signals corroborating each other, not just running in parallel.

## Phase 9 — External reputation signal (the one architectural gap, not just a tuning gap)

Dictionary-style DGA (`vawtrak`, `gozi`, `matsnu` — still 15-44% recall
after everything else in this plan) has a real ceiling for any classifier
that only ever sees the domain string once. The single most predictive
real-world signal against this specific failure mode — used by every
production DGA-detection system that actually beats a pure classifier —
is **domain registration age**: a DGA domain is typically registered
minutes to hours before use; a legitimate two-word brand domain is not.
This system has no access to that signal today, and closing it requires
a live external dependency (WHOIS/RDAP lookup, or a passive-DNS/threat-
intel feed with registration-date data) — a real infrastructure and
cost decision, not a code change, and one that should be raised
explicitly rather than silently added. Flagging it here as the one gap
in this whole plan that isn't closeable with more retraining or more
already-downloaded data.

## Phase 10 — Multi-dataset validation (closes "proven once" → "proven repeatedly")

Both validated models are proven against exactly one real dataset each.
CTU-13 alone has 13 scenarios across multiple botnet families (Neris,
Rbot, Virut, Menti, Sogou, Murlo, NSIS, Donbot) — Phases 1 and 3 used only
4-5 of them. Extending the flow-autoencoder and rule evaluations across
*all 13* scenarios (not just the ones already extracted) turns "validated
against one real botnet campaign" into "validated across a real, diverse
set of them" — the difference between a lucky result and a robust one.
Same idea for the DGA benchmark: `benchmarks/real_dga_domains.csv` already
covers 25 families from one published dataset: a second, independent DGA
dataset (if one can be sourced as cleanly as CTU-13 was) would confirm
today's numbers aren't an artifact of this one benchmark's specific
domain generation.

---

## What "10/10" actually means, concretely

Not a bigger model, again — a system where:
1. 🟡 Every detection category the platform claims to have has been
   checked against real attack data at least once — 5 of 6 now (DGA,
   flow anomaly, and 3 of `evaluate_rules()`'s 4 remaining rules); only
   JA4 fingerprinting is still unchecked, blocked on sourcing a real
   TLS-fingerprint feed rather than anything already on disk (Phase 6).
2. ✅ A false-positive mode nobody had looked for yet (DNS-burst on
   benign traffic) got found and fixed before a real deployment found it
   first — and it was real, not hypothetical: 100% false-positive rate
   at the original threshold, confirmed with 200 real-domain trials
   (Phase 5).
3. ✅ A future regression in *any* validated detector — not just the DGA
   model — is caught by CI before merge: verified by simulating a real
   regression against each new gate and confirming it fails the build
   (Phase 7).
4. An incident's reported confidence reflects how many independent
   signals corroborate it, not just whichever detector happened to fire
   first (Phase 8).
5. The one remaining hard problem (dictionary DGA) has an honestly-scoped
   answer — a named external dependency to add, not a vague "needs more
   research" (Phase 9).
6. Today's real numbers are shown to hold up across many real scenarios,
   not one lucky benchmark each (Phase 10).

Phases 5, 6, and 7 are done (6 partially). Effort for the rest: Phase 8
is the real project-sized piece here, similar scope to the original
roadmap's Phase 2. Phase 9 is a real infrastructure/cost decision to
raise with whoever owns that call, not a solo coding task. Phase 10 is
mostly re-running Phase 1/3/6's already-built scripts against more of
what's already downloaded — plus, now, a second independent dataset
before retuning Phase 6's three weak rules, to avoid validating a fix
against the same data that found the gap.
