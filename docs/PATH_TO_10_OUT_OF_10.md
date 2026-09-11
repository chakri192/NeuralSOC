# Path to 10/10

Honest starting point, not a sales pitch: two of six detection categories
(DGA, flow anomaly) are now validated against real attack data and hold up
well. Of the other four, three now have real numbers too — one
(Reconnaissance) genuinely works, three others (DDoS, C2, Exfil) barely
fire on real traffic. Detectors now combine into one calibrated
per-incident score instead of firing independently, and that combination
is itself measured against real data: 53.7% recall at 98.8% precision,
beating the best single detector alone. Every validated model/rule/
composite-score is still proven against exactly one real dataset, not
several — see Phase 10.

Ordered by how directly each phase closes a *named* gap from the honest
assessment above, cheapest first. CTU-13 (already downloaded, CC-BY,
[docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md) has the full citation)
covers most of Phases 5-6 with zero new data-sourcing — a deliberate
choice: reuse what's already been paid for in download time before going
back to the well for a new dataset.

**Phases 5, 6, 7, and 8 are done** (6 partially — JA4 still needs new
data). 5 and 6 found real, previously-unmeasured gaps, not false alarms:
Phase 5's DNS burst detector had a 100%-reproducible false-positive bug;
Phase 6 found that only 1 of 4 newly-validated rules actually works well
against real attack traffic. Phase 7 makes sure none of it regresses
silently: every validated detector — DGA, flow anomaly, the 4 rules, and
now the composite score itself — has the same CI-enforced real-world
regression gate. Phase 8 combined all of it into one calibrated
per-incident score and proved, against real data, that the combination
genuinely catches more than any single detector alone. See each phase
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

**Status: done.** `inference/risk.py`'s `calculate_risk_score()` now
combines each incident's distinct detectors via log-odds pooling instead
of a flat severity-bucket-plus-volume heuristic that ignored
`confidence_score` entirely and let repeated firings of the same
detector (224 duplicate `RULE_DNS_QUERY_BURST` alerts from one ongoing
DNS burst, observed live this session) inflate risk linearly.

**Measured against real data**
(`scripts/evaluate_composite_scoring_against_real_data.py`, real CTU-13
flows through the flow autoencoder + all 4 rules): combining detectors
catches **53.7% of real botnet flows at 98.8% precision**, versus 48.5%
for the best single detector alone — this is the "recall and precision
improve together" promise actually delivered, not just reframed. Also
surfaced a genuinely new finding along the way: the flow autoencoder's
headline 99.8% recall (Phase 3) is against one held-out scenario; across
all 13 real scenarios it catches only ~37% alone, a materially more
honest picture that directly motivates Phase 10 below.

**A second real bug, found while wiring this in:**
`IncidentCorrelator.add_alert()`'s `threshold` parameter had been dead
code — accepted, never read — so no risk-score filter existed at all
despite the parameter's name implying one. Now it gates real incident
publication, calibrated the same way as every other threshold in this
project: a real sweep found the naive inherited default (80) actually
made the composite score perform *worse* than trusting the single best
detector (26.3% vs. 48.5% recall); 50 is the real, evidence-based value.

Full writeup, numbers, and the exact log-odds formula in
[SECURITY.md](../SECURITY.md#composite-incident-scoring). Also gated by
a CI regression check, same as every other detector in this plan.

## Phase 9 — External reputation signal (the one architectural gap, not just a tuning gap)

**Status: signal validated with real data; infrastructure decision still
open, deliberately not made unilaterally — see below.**

Dictionary-style DGA (`vawtrak`, `gozi`, `matsnu` — still 15-44% recall
after everything else in this plan) has a real ceiling for any classifier
that only ever sees the domain string once. Domain registration age is
the standard production signal against this specific failure mode. This
plan originally claimed DGA domains are "typically registered minutes to
hours before use" — that was an unverified industry generalization, not
something checked against this project's own real data. It's now been
checked, and the real picture is more nuanced:

**Real RDAP lookups against the 7 genuinely suspicious domains from the
real Lumma Stealer capture** (free, public `rdap.org`, no cost, no data
committed anywhere it wasn't already public):

| Domain | Registered | Days before capture (2026-01-31) |
|---|---|---|
| `holiday-forever.cc` | 2026-01-22 | 9 |
| `whooptm.cyou` | 2026-01-13 | 18 |
| `megafilehub4.lat` | 2025-12-24 | 38 |
| `communicationfirewall-security.cc` | 2025-12-16 | 46 |
| `filemegahab4.sbs` | 2025-12-09 | 53 |
| `hiyter.com` | 2025-05-15 | 261 (~8.7 months) |
| `whitepepper.su` | — | **no RDAP service available for `.su`** |

Compared against real legitimate domains (`google.com`: 1997,
`microsoft.com`: 1991, `wikipedia.org`: 2001, `github.com`: 2007) — the
separation is real and would be easy to threshold on (days-to-months old
vs. decades old), but two honest caveats this plan's original framing
missed entirely:

1. **"Minutes to hours" was wrong.** These domains were registered days
   to months ahead of use, not immediately before — malware operators
   evidently pre-register infrastructure in batches. A signal built on
   the "minutes to hours" assumption would have missed all seven of these.
2. **Coverage gap that specifically hurts on the traffic that matters
   most.** `whitepepper.su` — the domain queried 10 times in a real
   beaconing pattern, arguably the single strongest signal in the whole
   capture — has **no RDAP data available at all**. `.su` and several
   other cheap TLDs real malware favors (`.cc`, `.lat`, `.cyou`, `.sbs`
   all resolved fine here, but coverage varies by TLD and registrar) have
   inconsistent or absent registration transparency — not a coincidence;
   it's part of why malware operators use them. A domain-age signal's
   real-world coverage is weaker specifically where it's needed most.

**Infrastructure options, for whoever makes this call** (not decided
here):
- **Free public RDAP** (what validated the table above): no cost, no
  API key, but real-time per-query network calls (100-500ms+ latency —
  belongs in an async enrichment stage like `ThreatEnricher`, not the
  hot classification path), inconsistent TLD coverage, and a genuine
  privacy consideration: every domain sent for lookup leaves the
  organization's network, which is a real question for a product
  monitoring potentially sensitive internal DNS traffic (mitigated if
  restricted to only CNN-flagged/already-suspicious domains, not every
  query).
- **Commercial passive-DNS/WHOIS-history feeds** (WhoisXML, SecurityTrails,
  DomainTools): paid, but bulk/cached lookups, SLAs, and historical WHOIS
  data current lookups can't see (privacy-service-obscured current
  records sometimes still expose original registration history). A real
  procurement/budget decision.
- **Local zone-file-based lookup**: some registries publish daily
  newly-registered-domain zone files (e.g. ICANN's Centralized Zone Data
  Service); building a local table avoids per-query external calls and
  the privacy exposure entirely, at the cost of more infrastructure to
  stand up and maintain.

This is exactly the kind of decision this plan flagged from the start as
not a solo coding task — a real cost/privacy/architecture trade-off, now
backed by real evidence instead of a hypothesis, for whoever owns that
call to actually make.

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
4. ✅ An incident's reported confidence reflects how many independent
   signals corroborate it, not just whichever detector happened to fire
   first — and combining them measurably catches more real attacks
   (53.7% vs. 48.5% recall for the best single detector), not just a
   reshuffled number (Phase 8).
5. 🟡 The one remaining hard problem (dictionary DGA) has an honestly-
   scoped, *evidence-checked* answer, not a vague "needs more research"
   or an untested industry generalization — real RDAP lookups against
   the real Lumma capture's malicious domains confirmed the signal
   works but corrected the original "minutes to hours" assumption
   (real gap: days-to-months) and found a real coverage hole on exactly
   the cheap TLDs malware favors. The actual infrastructure/cost
   decision is still open, deliberately (Phase 9).
6. Today's real numbers are shown to hold up across many real scenarios,
   not one lucky benchmark each (Phase 10) — Phase 8's own evaluation
   already surfaced a concrete reason this matters: the flow
   autoencoder's 99.8% recall (Phase 3) drops to ~37% across all 13 real
   scenarios instead of the one it was validated against.

Phases 5, 6, 7, and 8 are done (6 partially). Effort for the rest: Phase
9 is a real infrastructure/cost decision to raise with whoever owns that
call, not a solo coding task. Phase 10 is mostly re-running Phase
1/3/6/8's already-built scripts against more of what's already
downloaded — plus, now, a second independent dataset before retuning
Phase 6's three weak rules, to avoid validating a fix against the same
data that found the gap.
