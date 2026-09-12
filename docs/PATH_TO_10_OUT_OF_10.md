# Path to 10/10

Honest starting point, not a sales pitch: two of six detection categories
(DGA, flow anomaly) are now validated against real attack data and hold up
well. Reconnaissance genuinely works; DDoS, C2 Beaconing, and Data
Exfiltration were all fixed with a genuinely different, windowed
detector once single-flow tuning proved structurally incapable.
Detectors now combine into one calibrated per-incident score instead of
firing independently, and that combination is itself measured against
real data: all seven detectors together (including the three windowed
ones) catch 52.5% of real botnet connections at 98.8% precision — a real
+7.3-point improvement over the best single detector alone (45.1%, the
flow autoencoder). The flow autoencoder and DGA CNN are now each
validated against a second, independent real dataset too — see Phase 10
— though the rule-based detectors still only have one real dataset
(CTU-13) behind it.

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

**Status: Reconnaissance validated; DDoS, C2 Beaconing, and Data
Exfiltration all validated AND fixed with a genuinely different
detector; JA4 remains blocked on new data.**

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

**DDoS, C2 Beaconing, and Data Exfiltration: all fixed, not retuned —
every one of these three real gaps was structural, not a tuning gap.**
An exhaustive real threshold sweep (not a quick guess) found no
single-flow threshold could ever fix any of them: a real volumetric
flood is many connections arriving fast, real C2 beaconing is a regular
interval between many connections, and real bulk exfiltration is a real
total moved across many smaller transfers over time — none of these is
a property any one flow's own fields encode. Built
`inference/conn_behavior.py`'s `ConnBehaviorTracker` instead — the same
"stateful window instead of a single-event check" fix Phase 5's DNS
burst detector already uses — calibrated against the real, raw CTU-13
`.binetflow` files (real source/destination IPs and timestamps, which
the sampled `real_rule_validation_dataset.csv` extract above doesn't
carry). Measured against the real production tracker class itself:
`RULE_DDOS_CONN_RATE` reaches 100% precision / 11.3% recall / 0.00% FPR
(versus the old single-flow rule's 55.3%/0.2%/0.14%) and
`RULE_EXFIL_BYTE_VOLUME` reaches ~100% precision / 22.2% recall / 0.01%
FPR (versus the old single-flow rule's 100%/0.3%/0.00% — same precision,
74x the recall) — both real improvements on every axis, not trade-offs.
`RULE_C2_BEACON_PERIODIC` is real but standalone-weaker in a different
way: a fine real threshold sweep found its recall is a flat ~0.2-0.4%
ceiling no threshold moves, so its one calibrated parameter is tuned
purely for precision/FPR instead (37.0% precision / 0.3% recall / 0.58%
FPR) — and its confidence is deliberately kept below 0.5 regardless — a
lone firing can never by itself cross Phase 8's log-odds-pooled incident
threshold; it corroborates rather than standing alone. Full numbers, the
real false-positive mode found along the way (a NAT/gateway host that
looked like a bigger flood than the real attackers until the check was
scoped to a (source, destination) pair), CTU-13's own real C2-channel
ground truth, and a real fakeredis/mocking interaction bug found by a
live pytest run (not an isolated script) are all in
[SECURITY.md](../SECURITY.md#windowed-connection-behavior-detection-ddos-rate-c2-periodicity--bulk-exfil).

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
originally caught 53.7% of real botnet flows at 98.8% precision, versus
48.5% for the best single detector alone — the "recall and precision
improve together" promise actually delivered, not just reframed. Also
surfaced a genuinely new finding along the way: the flow autoencoder's
headline 99.8% recall (Phase 3) is against one held-out scenario; across
all 13 real scenarios it catches only ~37-45% alone (the exact figure
moves with dataset sampling — see below), a materially more honest
picture that directly motivated Phase 10.

**Re-measured after Phase 10's own DDoS/C2/exfil work folded in three
more detectors** (`RULE_DDOS_CONN_RATE`, `RULE_C2_BEACON_PERIODIC`,
`RULE_EXFIL_BYTE_VOLUME`) against a new, comprehensive, uncapped real
dataset (`benchmarks/real_composite_dataset.csv`) carrying every field
all seven detectors need: **52.5% recall at 98.8% precision**, a real
+7.3-point improvement over the best single detector alone (45.1%, the
flow autoencoder). The recall figure moved from 53.7% for a disclosed,
non-regression reason — it now reflects the full, naturally-weighted
real CTU-13 population instead of an equal-per-scenario capped sample —
not because corroboration stopped working. Bulk-exfil's own solo recall
(22.2%) is real, but its *incremental* contribution to the union was
modest (52.1% → 52.5%): many of the real flows it independently catches
were already caught by the flow autoencoder or another detector on the
same underlying attack.

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

**Status: done.** Free-RDAP, async-enrichment-only option built
(`inference/domain_age.py`), wired into `inference/stream_processor_faust.py`
behind the existing DGA CNN's `is_dga` gate (never looked up for every DNS
query, only for domains the CNN already flagged — see that module's
docstring), and validated live against the real Lumma Stealer capture. A
real integration bug was found and fixed during that live validation —
see below.

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

**What got built**: `DomainAgeLookup` (free public RDAP via `rdap.org`'s
bootstrap, which redirects to whichever registry actually holds a TLD's
records — Verisign for `.com`, CentralNic for `.sbs`/`.cyou`, etc.),
`extract_registrable_domain()` (SSRF-conscious SLD extraction, validated
before ever touching a request URL), and `confidence_for_age()` (linear
0.55-0.95 confidence scaled by how far under the 180-day
`YOUNG_DOMAIN_DAYS_THRESHOLD` a domain is — calibrated against the 9-261
day real range above). A hit becomes a second, independent
`RULE_DOMAIN_AGE_YOUNG` detection alongside the CNN's own verdict, combined
via `inference/risk.py`'s log-odds pooling (Phase 8) rather than a
standalone confirm/deny — deliberately, since a young-but-legitimate
domain is a real, known false-positive mode for this signal alone.
Result-caching (24h TTL, 5000-entry bound) keeps repeated queries for the
same domain from re-hitting RDAP. `k8s/cilium-identity-policy.yaml` gained
a `toFQDNs: rdap.org` egress rule, with an honest limitation documented
inline: RDAP's redirect-to-registry design means a strict per-registry
FQDN allow-list isn't practically enumerable.

**A real integration bug, found by live verification, not by unit
tests.** Every unit test passed against mocks, and live logs showed real
200 OK RDAP responses for the exact malicious domains above — yet
`RULE_DOMAIN_AGE_YOUNG` never fired. Root cause: `_parse_age_days()` used
`datetime.fromisoformat()`, which only accepts single-digit fractional
seconds (RDAP's actual `eventDate` format, e.g.
`"2025-12-09T08:20:51.0Z"`) starting in Python 3.11 — this project runs
3.10, where every real RDAP response raised `ValueError`, silently
swallowed by the function's fail-closed `except` clause into "no signal,"
with nothing logged to point at why. Fixed by switching to
`dateutil.parser.isoparse` — already a project dependency, already used
the same way in `shared/formatters.py`. Confirmed fixed directly against
the real Lumma domains: `filemegahab4.sbs` and `whooptm.cyou` now return
real, correct ages instead of `None`.

**A second, honest finding from the same live re-verification, about
testing methodology rather than code**: replaying the original 2026-01-31
pcap capture live today (many months later) no longer demonstrates
`RULE_DOMAIN_AGE_YOUNG` firing for any of the table's malicious domains —
because domain age is computed relative to wall-clock "now" at lookup
time, and every one of those domains has since aged past the 180-day
threshold in the real time that's elapsed since the capture (e.g.
`filemegahab4.sbs` was 53 days old at capture time; it measures ~276 days
old today). This is expected, correct behavior for a point-in-time signal,
not a defect — but it does mean this specific aged pcap can no longer
prove the "young → alert" branch live end-to-end; a fresh capture (or a
domain registered within the last 180 days) would be needed to demonstrate
that branch live again. That branch itself is still verified — via
`tests/test_pipeline.py`'s
`test_domain_age_publishes_a_second_alert_for_a_young_cnn_flagged_domain`
and `test_domain_age_not_looked_up_when_cnn_does_not_flag_the_domain`,
which exercise the exact same production code path, substituting a
controlled age for the (now independently-confirmed-correct) real network
call.

**Options not taken, for the record**: commercial passive-DNS/WHOIS-history
feeds (WhoisXML, SecurityTrails, DomainTools) would add bulk/cached
lookups, SLAs, and historical WHOIS visibility current lookups can't get,
at real procurement cost. A local zone-file-based lookup (e.g. ICANN's
Centralized Zone Data Service) would avoid per-query external calls and
the privacy exposure of the free-RDAP path entirely, at the cost of more
infrastructure to stand up and maintain. Free RDAP was chosen as the
lowest-cost option that still closes the gap; either alternative remains
available if free RDAP's coverage or latency prove insufficient in
practice.

## Phase 10 — Multi-dataset validation (closes "proven once" → "proven repeatedly")

**Status: partially done.** Both validated models were originally proven
against exactly one real dataset each. CTU-13 alone has 13 scenarios
across multiple botnet families (Neris, Rbot, Virut, Menti, Sogou, Murlo,
NSIS, Donbot) — Phases 1 and 3 used only 4-5 of them.

**The rule-based detectors and flow autoencoder's all-13-scenario
coverage: done.** `benchmarks/real_rule_validation_dataset.csv` (Phase
6/7) already spans all 13 real CTU-13 scenarios, so the 4 rule-based
detectors were already validated across all of them, not just a handful.
The flow autoencoder's all-13-scenario number existed too, but only as a
one-off finding buried inside the composite-scoring evaluator with no
baseline of its own — formalized this session as its own independent,
CI-gated check
(`scripts/evaluate_flow_autoencoder_against_real_data.py`,
`benchmarks/flow_autoencoder_all_scenarios_baseline.json`): 36.9% recall
across all 13 scenarios versus 99.8% on the single held-out scenario it
was originally validated against — a real, now permanently-guarded gap
between "validated against one real botnet campaign" and "validated
across a real, diverse set of them." See
[SECURITY.md](../SECURITY.md#flow-autoencoder-validation-against-real-world-data)
for the full writeup and the regression-catch verification.

**The second, independent DGA dataset: done.** Sourced UMUDGA (Zago et
al., *Data in Brief*, 2020, MIT licensed — real malware DGA
implementations actually executed, not wire-observed like the first
dataset's Cucchiarelli source) for the malicious side, and Tranco (not
Alexa) for the benign side, since UMUDGA's own benign set turned out to
be built from English-word combinations rather than verified-real
registered domains. Verified independence directly (0.07% exact-domain
overlap with the first dataset) before trusting any of it. Measured live
against the exact same shipped model: **86.3% precision / 75.8% recall /
12.0% FPR**, versus the first dataset's 84.6%/77.2%/13.9% — remarkably
close, real evidence today's numbers generalize across two
independently-sourced real datasets rather than being an artifact of one
benchmark's specific construction. One honest limitation, disclosed
rather than worked around: UMUDGA's public metadata never exposes which
of its 51 domain-list folders is which named malware family (only Locky
was identifiable), so malicious rows are grouped by an anonymized but
fully traceable group id (`benchmarks/umudga_group_manifest.csv` maps
each back to its exact source folder) rather than a guessed, possibly
wrong, family name. Now its own independent CI gate
(`scripts/evaluate_against_second_dga_dataset.py`,
`benchmarks/dga_second_dataset_baseline.json`), verified to actually
catch a regression the same way as every other gate in this document.
See [SECURITY.md](../SECURITY.md#model-validation-against-real-world-data)
for the full writeup.

**Nothing left open here.** DDoS, C2 Beaconing, and Data Exfiltration
all turned out not to need a second dataset at all — Phase 6's own
update above found their real gap was structural (a single flow can't
encode a multi-connection pattern), fixed with a windowed detector
instead of a retune. Exfiltration's own initial sweep looked like it
might need one (real recall capped around 1.5% via any single-flow
threshold, consistent with bulk-exfiltration-shaped SINGLE FLOWS being
rare in CTU-13's real botnet behavior) — but the real fix turned out to
be the same shape as DDoS: summing bytes per (source, destination) pair
over a window instead of checking any one connection's own byte count
found the real pattern was there all along, just spread across many
smaller transfers (`RULE_EXFIL_BYTE_VOLUME`, 22.2% recall at ~100%
precision). No genuinely different network-flow rule in this project
still needs a second dataset before a real fix can be validated.

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
   (52.5% vs. 45.1% recall for the best single detector, now across all
   seven detectors including the windowed DDoS-rate/C2-periodicity/
   exfil-byte-volume trio), not just a reshuffled number (Phase 8).
5. ✅ The one remaining hard problem (dictionary DGA) has a built,
   live-verified answer, not a vague "needs more research" or an untested
   industry generalization — real RDAP lookups against the real Lumma
   capture's malicious domains confirmed the signal works, corrected the
   original "minutes to hours" assumption (real gap: days-to-months), and
   found a real coverage hole on exactly the cheap TLDs malware favors
   (`.su`, zero RDAP coverage). Domain-age lookup is now built and wired
   in as a second, independent signal combined via Phase 8's log-odds
   pooling — live re-verification against the real pcap surfaced and
   fixed a real Python-3.10 date-parsing bug in the process (Phase 9).
6. ✅ Today's real numbers are shown to hold up across many real
   scenarios and against a second, independent dataset, not one lucky
   benchmark each: the 4 rule-based detectors and flow autoencoder are
   validated across all 13 real CTU-13 scenarios (its 99.8% recall from
   Phase 3 drops to 36.9% there, and that gap is now independently
   CI-gated so it can't regress unnoticed), and the DGA CNN's numbers
   (84.6%/77.2%/13.9%) hold up nearly unchanged (86.3%/75.8%/12.0%)
   against UMUDGA + Tranco, a second real dataset built from a
   genuinely different malicious-domain-generation methodology and a
   different benign source — real evidence today's numbers aren't an
   artifact of any one benchmark's specific construction (Phase 10).

Phases 5, 7, 8, 9, and 10 are done (6 partially — Reconnaissance and now
DDoS, C2 Beaconing, and Data Exfiltration are all done, JA4
fingerprinting remains the one detection category still blocked on new
data sourcing). What's left is narrow: JA4 needs a real malicious
JA3/JA4 fingerprint feed (Abuse.ch), not something already on disk.
