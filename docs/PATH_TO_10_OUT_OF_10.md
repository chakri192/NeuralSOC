# Path to 10/10

Honest starting point, not a sales pitch: two of six detection categories
(DGA, flow anomaly) are now validated against real attack data and hold up
well. The other four have never been checked against anything but this
repo's own simulator. Every detector fires independently into one flat
alert stream — nothing combines their signals into one calibrated
per-incident confidence. And the two validated models are each proven
against exactly one real dataset, not several. That's the gap between
"genuinely good, evidence-backed" (where this is today) and 10/10.

Ordered by how directly each phase closes a *named* gap from the honest
assessment above, cheapest first. CTU-13 (already downloaded, CC-BY,
[docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md) has the full citation)
covers most of Phases 5-6 with zero new data-sourcing — a deliberate
choice: reuse what's already been paid for in download time before going
back to the well for a new dataset.

**Phase 5 is done** — and it wasn't a false alarm: a real, 100%-reproducible
false-positive mode was found and fixed. See Phase 5 below for the numbers.

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

DGA and flow anomaly are 2 of 6. `evaluate_rules()`'s other four rules
(C2 Beaconing, Reconnaissance, Volumetric DDoS, JA4 fingerprinting) have
**never been run against real attack data** — every claim made about them
so far is against this repo's own synthetic simulator only.

- **C2 Beaconing and Reconnaissance — no new data needed.** CTU-13's
  `.binetflow` files (already extracted for Phases 1/3) carry exactly the
  fields these rules need: `State` (e.g. `S0` = connection attempt, no
  reply — Reconnaissance's own signature), packet/byte counts, and
  inter-flow timing per source host. The dataset's whole premise is real
  botnet C2 traffic, so real beaconing patterns are already sitting in
  data this project has paid the download cost for. Build
  `scripts/evaluate_rules_against_real_data.py` mirroring the two
  existing real-data evaluators, feeding real CTU-13 rows through
  `evaluate_rules()` directly (no model loading needed — these are pure
  functions).
- **Volumetric DDoS — also covered by CTU-13.** Scenario 9's own capture
  is literally named `botnet-capture-20110815-rbot-dos` — a real DDoS
  campaign is already in the downloaded archive, just not yet extracted
  (`CTU-13-Dataset/4/` in the archive's numbering, per the file listing
  from Phase 3's extraction).
- **JA4 fingerprinting is the one genuine new-data-sourcing item.**
  Needs real TLS handshakes with known-malicious JA4 fingerprints — a
  different kind of dataset than network-flow records. Abuse.ch's
  feeds (SSLBL/ThreatFox) publish real malicious JA3/JA4 fingerprints
  associated with actual malware families; cross-referencing those
  against JA4s extracted from a real malware pcap (the Lumma capture
  already in `/tmp`, or a new one) would close this the same way DGA/flow
  validation did. Flag before starting: confirm Abuse.ch's terms permit
  this use, the same diligence already applied to CTU-13/baderj's repo.

Each of these should get its own committed benchmark CSV and evaluation
script, matching the DGA/flow pattern exactly — not a one-off scratch
check.

## Phase 7 — CI gate parity (cheap, mechanical, currently a real gap)

The DGA model has a CI regression gate (`.github/workflows/ci.yml`'s "DGA
model real-world regression gate" step, added this session). **The flow
autoencoder's real 100%/99.8%/0.00% result has no equivalent CI
protection** — nothing stops a future retrain from silently regressing it
back toward the ~98% FPR it started at. This is a same-day fix once Phase
6's other evaluators exist: add one CI step per validated detector, each
failing the build on a real-world regression. Effort: an hour, most of it
just wiring up what Phase 5/6 will have already built.

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
1. Every detection category the platform claims to have has been checked
   against real attack data at least once, not just 2 of 6 (Phase 6).
2. ✅ A false-positive mode nobody had looked for yet (DNS-burst on
   benign traffic) got found and fixed before a real deployment found it
   first — and it was real, not hypothetical: 100% false-positive rate
   at the original threshold, confirmed with 200 real-domain trials
   (Phase 5).
3. A future regression in *any* validated detector — not just the DGA
   model — is caught by CI before merge (Phase 7).
4. An incident's reported confidence reflects how many independent
   signals corroborate it, not just whichever detector happened to fire
   first (Phase 8).
5. The one remaining hard problem (dictionary DGA) has an honestly-scoped
   answer — a named external dependency to add, not a vague "needs more
   research" (Phase 9).
6. Today's real numbers are shown to hold up across many real scenarios,
   not one lucky benchmark each (Phase 10).

Phase 5 is done. Effort for the rest if picked up in order: Phase 6 is
2-3 days (C2/Recon/DDoS need no new data; JA4 does). Phase 7 is an hour
once Phase 6 lands. Phase 8 is the real project-sized piece here, similar
scope to the original roadmap's Phase 2. Phase 9 is a real
infrastructure/cost decision to raise with whoever owns that call, not a
solo coding task. Phase 10 is mostly re-running Phase 1/3/6's
already-built scripts against more of what's already downloaded.
