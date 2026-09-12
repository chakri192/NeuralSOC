# Path to 10/10

Honest starting point, not a sales pitch: two of six detection categories
(DGA, flow anomaly) are now validated against real attack data and hold up
well. Reconnaissance genuinely works; DDoS, C2 Beaconing, and Data
Exfiltration were all fixed with a genuinely different, windowed
detector once single-flow tuning proved structurally incapable.
Detectors now combine into one calibrated per-incident score instead of
firing independently, and that combination is itself measured against
real data: all seven detectors together (including the three windowed
ones) catch 53.0% of real botnet connections at 98.3% precision. The flow
autoencoder was later retrained on a much broader real dataset (12 CTU-13
scenarios instead of 3), which raised its own real, leak-free
generalization recall from 36.9% to 54.5% — high enough that the
composite's lead over the best single detector alone shrank from +7.3
points to +0.4, since the flow autoencoder alone now catches almost
everything the rule-based detectors used to add on top of it (see Phase
10.5). The flow autoencoder and DGA CNN are now each validated against a
second, independent real dataset too — see Phase 10 — though the
rule-based detectors still only have one real dataset (CTU-13) behind it.

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
detector; JA4 investigated against a real malware pcap and found not
viable without a broader feed — a genuine negative result, not an
unstarted gap.**

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
way: an original fine CV threshold sweep (0.005-0.20) found a flat
~0.2-0.4% recall ceiling — root-caused later (Phase 10.6) as a
window-size problem, not a threshold one: real beacon intervals often
run 30-90+ minutes, far longer than the original 30-minute window could
ever hold enough observations for. After widening the window and
re-sweeping CV past the original 0.20 boundary, this detector now
measures 65.7% precision / 2.92% recall / 1.91% FPR — an ~11x real
recall improvement that also improves precision (see Phase 10.6). Its
confidence is still deliberately kept below 0.5 regardless — a lone
firing can never by itself cross Phase 8's log-odds-pooled incident
threshold; it corroborates rather than standing alone. Full numbers, the
real false-positive mode found along the way (a NAT/gateway host that
looked like a bigger flood than the real attackers until the check was
scoped to a (source, destination) pair), CTU-13's own real C2-channel
ground truth, and a real fakeredis/mocking interaction bug found by a
live pytest run (not an isolated script) are all in
[SECURITY.md](../SECURITY.md#windowed-connection-behavior-detection-ddos-rate-c2-periodicity--bulk-exfil).

**JA4 fingerprinting: real data investigated TWICE, independently, same
negative result both times — this is now a closed, well-understood
question, not an open gap.** CTU-13's flow records carry no TLS handshake
data, but the real Lumma Stealer pcap already used throughout this
document does — real `ja4plus` extraction against its real
`ClientHello`s, cross-referenced against the 7 already-confirmed-malicious
domains, found the malware's C2 traffic shares its exact JA4 fingerprint
with real Microsoft/Akamai traffic on the same infected machine (72%
precision even on this small, balanced comparison, likely worse at
real-world base rates) — consistent with this malware not implementing
its own TLS stack.

A second, independent investigation (enterprise-grade push, since CTU-13's
own "botnet-only" per-scenario pcaps turned out to be real and downloadable
despite the full-traffic captures never being published) found the same
root cause a different way: 427 real `ClientHello`s extracted across 9
real CTU-13 botnet pcaps collapsed to just 5 unique JA4 fingerprints,
**shared between two genuinely unrelated real malware families** (Neris
and Virut) captured on different dates — direct evidence the fingerprint
reflects a shared, period-correct Windows TLS stack, not either malware's
own implementation. No honest same-dataset FPR was even measurable this
time: the one real "confirmed-clean" CTU-13 capture available
(`normal-capture-20110817.pcap`) has zero TLS traffic at all, a real
artifact of the dataset's 2011-era timeframe (HTTPS wasn't yet pervasive
for ordinary desktop use, unlike the malware's own C2 already using it).

The extraction pipeline itself is now proven and reusable against any
future malware sample or dataset; both specific findings are real reasons
not to ship a rule seeded from either investigation, not a
data-unavailability gap — that gap is now closed. A real, broadly-curated
malicious JA4 feed (Abuse.ch, FoxIO's own community database) — checked
for real usage terms first, the same diligence already applied to
CTU-13/baderj's repo — remains the only path to a rule that could
actually discriminate, since it's the sole approach that could separate
"genuinely malware-specific" fingerprints from "commodity OS networking
stack" noise across enough independent malware families to matter, and
even then either specific family investigated here may simply not be
catchable this way at all.
Full numbers in
[SECURITY.md](../SECURITY.md#rule-based-detector-validation-against-real-world-data).

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

**Re-measured again after Phase 10.5's flow-autoencoder retrain**
(broadened from 3 real training scenarios to 12 — see Phase 10.5 below):
**53.0% recall at 98.3% precision, 1.16% FPR**. Composite's lead over the
best single detector alone shrank from +7.3 points to +0.4 (flow
autoencoder alone now measures 52.6% recall on this script's own
dataset) — a real, disclosed trade-off, not a regression: the flow
autoencoder's own recall genuinely improved, which is why the rule-based
detectors have less *incremental* headroom left to add on top of it.
Composite FPR rose from 0.80% to 1.16% for the same reason, tracking the
flow autoencoder's own FPR increase.

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
`benchmarks/flow_autoencoder_all_scenarios_baseline.json`): originally
36.9% recall across all 13 scenarios versus 99.8% on the single
held-out scenario it was originally validated against — a real, now
permanently-guarded gap between "validated against one real botnet
campaign" and "validated across a real, diverse set of them." That gap
was later substantially closed, not just guarded, by broadening
training itself — see Phase 10.5. See
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

## Phase 10.5 — Broaden the flow autoencoder's real training data (enterprise-grade push)

**Status: done.** Phase 10's all-13-scenario gate found the flow
autoencoder trained on only 3 of CTU-13's 13 scenarios (5/7/12, 13,944
real rows) generalized far worse (36.9% recall) than its own narrow
scenario-11 holdout (99.8%) suggested. Rather than leaving that gap
permanently guarded, closed it directly: retrained on real Normal flows
from all 12 non-held-out scenarios (281,892 rows, a 20x increase),
splitting each scenario's rows 80/20 *before* combining so the withheld
20% (`benchmarks/real_flow_dataset_normal_holdout.csv`) could still
measure real, non-leaked FPR.

Broadening training this way created a real, structural problem for the
Phase 10 all-scenarios gate itself: most of `real_rule_validation_dataset.csv`'s
Normal rows (every scenario but 11) are now the same rows the model was
fit to, which would have made that gate's own FPR quietly optimistic
going forward. Fixed by changing what the gate measures FPR against —
only scenario 11's Normal rows plus the withheld 20% holdout file, both
genuinely never seen during training — while recall still uses every
real Botnet row across all 13 scenarios (never at risk, since Botnet
rows are never part of training regardless of scenario or split).

A fine threshold sweep against this leak-free real dataset (mirroring
every other threshold decision in this project) found a sharp cliff in
the real Botnet reconstruction-error distribution around 0.00086-0.00088,
and settled on **0.0008** (`FLOW_ANOMALY_THRESHOLD`) — replacing the
prior 0.013.

**Result:** all-13-scenario recall **36.9% → 54.5%** (+17.6 points),
precision 99.3% → 95.8% (-3.5 points), FPR 0.21% → 0.63% (+0.42 points).
The scenario-11 holdout gate stayed effectively unchanged (100%/99.8%/
0.11%). Composite's own numbers moved to 53.0% recall / 98.3% precision
/ 1.16% FPR, and composite's lead over the best single detector shrank
from +7.3 points to +0.4 — a disclosed, expected consequence of the
flow autoencoder itself getting meaningfully better, not a regression.
Full writeup:
[SECURITY.md](../SECURITY.md#broadened-retrain-3-scenarios-to-12-real-held-out-fpr-still-enforced).

## Phase 10.6 — Fix the C2-periodicity detector's window size (enterprise-grade push)

**Status: done.** `RULE_C2_BEACON_PERIODIC`'s original fine CV-threshold
sweep (0.005-0.20) found a flat ~0.2-0.4% recall ceiling and concluded
most real "Botnet"-labeled connections simply aren't part of any
periodic C2 channel — true as far as it went, but a direct
inter-arrival-time analysis of every real CTU-13 botnet
(source, destination) pair found the real root cause instead: genuinely
near-perfect periodic beacons DO exist in the ground truth (coefficient
of variation as low as 0.0009), but often at 30-90+ *minute* real
intervals — far longer than `BEACON_WINDOW_SECONDS`'s original 1800s (30
minutes), which could never accumulate enough observations for those
pairs no matter how loose the CV threshold went. The original sweep
never tested past 0.20 either, leaving a real, usable signal region
entirely unexplored.

**Fixed directly:** widened the window to 21600s (6 hours), lowered the
minimum-observation floor from 5 to 3 (an imperfect real beacon
shouldn't need 5 *consecutive* clean intervals to qualify), then
re-swept CV past the original 0.20 ceiling. The real trade-off curve
doesn't cliff until beyond CV 0.9 (FPR jumps from ~2% to ~9%+ there);
0.5 was chosen as the value that stays within this project's own <2%
FPR budget for this detector while capturing the large majority of the
achievable gain.

**Result:** 65.7% precision / 2.92% recall / 1.91% FPR — versus the
original 37.0%/0.27%/0.58%, an **~11x real recall improvement that also
improves precision**, not a trade-off (0.008 was too strict on both
axes at once, chosen before the window-size root cause was known).
Also found and fixed a real, separate performance issue while widening
the window: `is_c2_beacon()` recomputed `statistics.mean()`/`stdev()`
(slow, exact-Fraction internals) over the whole window's history on
every single connection event — replaced with mathematically identical
plain-float arithmetic (verified to ~1e-14 precision), since a 12x-wider
window makes that per-call cost meaningfully more likely to matter for
busy pairs. Full writeup:
[SECURITY.md](../SECURITY.md#windowed-connection-behavior-detection-ddos-rate-c2-periodicity--bulk-exfil).

**Composite re-measured with this fix folded in:** 98.3% precision /
53.0% recall / 1.15% FPR — essentially unchanged from before the fix (a
genuine, disclosed finding: the beacon detector's own recall gain is
real but small next to composite's ~800k-row real population, and mostly
overlaps what other detectors already catch on the same attacks). Also
fixed the real infrastructure problem this fix exposed while validating
it: both real-data evaluators for this section took 30+ minutes once
`BEACON_WINDOW_SECONDS` widened to 6 hours (the real, Redis-backed
tracker's per-call cost scales with a busy pair's accumulated history).
`scripts/_fast_conn_behavior.py`'s pure-Python stand-in — verified to
make identical decisions via a real-data parity test
(`tests/unit/test_fast_conn_behavior.py`) — cut both evaluators to under
35 seconds combined, unblocking fast iteration for every future
detector-tuning workstream.

## Phase 10.7 — DGA CNN+BiLSTM architecture (investigated, reverted)

**Status: real investigation, honest negative result.** Also tried,
as part of the same enterprise-grade push: a bidirectional-LSTM branch
added to the DGA CNN for sequence-order signal the character-CNN can't
see. Root-caused and fixed a real, reproducible regression this
introduced in the `matsnu` family (long dictionary-word concatenations
with no separator lose signal under naive final-hidden-state LSTM
pooling; max-pooling over every timestep fixed it). But validated
against both of this project's real, independent DGA datasets across
five total retrains, the architecture as a whole never produced a run
that cleared both datasets' per-family regression gates at once — every
run traded some real family or group's recall for another's, including
a 38-point collapse on one UMUDGA group in the run that otherwise looked
best in aggregate. Reverted to the original, shipped CNN-only
architecture (confirmed byte-identical via SHA-256). Full investigation:
[docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md#phase-5--cnnbilstm-hybrid-investigated-not-shipped).

## Phase 10.8 — JA4, a second time: real CTU-13 botnet pcaps (negative result, confirmed)

**Status: done. Second independent negative result, closing this
question rather than leaving it open.** The Lumma investigation
(Phase 6) was one malware sample against one capture. CTU-13's own
regular full-traffic pcaps are never published for privacy, but each of
its 13 scenarios separately ships a real, non-truncated "botnet-only"
pcap (traffic captured on the infected VM's own interface) — real data
this project hadn't looked at yet. Downloaded 9 of these (~1.36GB, same
CC-BY host already used for the `.binetflow` archive) across 7 named
scenarios.

Only 4 of the 9 carried any TLS traffic at all (Rbot/Donbot/Sogou/Qvod's
captures had zero packets on port 443 — those families' real C2 used
other protocols). The two that did — real Neris and real Virut (CTU-13
labels some Virut scenarios "fast-flux" for the behavior demonstrated,
not the malware's name, confirmed against that scenario's own README) —
yielded 427 real `ClientHello`s across just **5 unique JA4 fingerprints
total, shared between both genuinely unrelated families**. That's
direct, structural evidence the fingerprints reflect a common
period-correct Windows TLS stack, not either malware's own
implementation — the same root cause as the Lumma finding, now
confirmed a second, independent way. No same-dataset FPR was even
measurable this time: the one real "confirmed-clean" CTU-13 capture
(`normal-capture-20110817.pcap`) has zero port-443 traffic at all, a
real artifact of the dataset's 2011-era timeframe.

**No JA4 rule is deployed, for the same reason both times.** The
extraction pipeline itself (real `ja4plus`, real pcap parsing, real RDAP
cross-referencing) is proven and reusable; what's proven not to work is
seeding a rule from a single dataset's malware samples, twice over now.
Full writeup:
[SECURITY.md](../SECURITY.md#rule-based-detector-validation-against-real-world-data).

## Phase 10.9 — DGA ensembling (investigated, not shipped)

**Status: real investigation, honest negative result.** The last
Workstream 2 idea: since Phase 10.7's CNN+BiLSTM attempt showed real,
substantial run-to-run training variance (unseeded training, aggregate
recall ranging 75.0%-79.5% across 4 retrains of one architecture), try
averaging predictions across several independent copies of the already-
proven CNN-only model instead of changing the architecture again.

Trained 2 more independent CNN-only models and combined them with the
shipped one into a 3-model ensemble. Re-swept the threshold for the
ensemble specifically (averaging shifts the score distribution, so the
shipped model's 0.97 doesn't transfer) and found 0.7 looked like a clean
win in aggregate: recall matched the shipped model almost exactly on
both real datasets while precision and FPR both improved. The full
per-family/per-group table said otherwise: `pushdo` regressed 11 points,
and `umudga_group_07` — the same UMUDGA group that collapsed 38 points
in Phase 10.7's best-looking CNN+BiLSTM run — **collapsed completely
(47.0% → 0.0%)** a third time, this time under a technique with no
recurrent branch involved at all. Three independent techniques now
converge on the same conclusion: this group's real domains sit on an
unstable decision boundary for this training pipeline as a whole,
because its synthetic generators never produce anything shaped like it
— not something architecture changes or ensembling can fix.

**Not shipped.** `models/cnn_dga.pt` reverted to the original shipped
weights (confirmed byte-identical via SHA-256).

**A fourth attempt, after pivoting from modeling to targeted synthetic
data, made it worse.** `umudga_group_07`'s real domains turned out to
follow one specific shape: a short random prefix concatenated with one
near-constant ~15-character tail — a pattern no existing generator
produced. Added a new generator matching that structural shape (never
reusing the real group's own literal content) and retrained, using the
same technique that already fixed conficker/pushdo/vawtrak earlier in
this project. It made the target group *worse* (47.0% → 2.3%, the worst
of any of the four attempts) and newly regressed three families on the
first dataset and two more UMUDGA groups on the second — more collateral
damage than any prior attempt. Likely cause: a small, fixed pool of
invented tail strings gave the model something narrow to memorize
rather than the general "long near-zero-entropy tail" principle that
would transfer to the real group's own different literal content.
Reverted both the model and the generator code.

**Four independent techniques have now failed on this one real gap —
this is a genuine, well-evidenced stopping point**, not a string of
unlucky attempts worth a fifth try. The honest state is the original
shipped model's own numbers (84.6%/77.2%/13.9% and 86.3%/75.8%/12.0%), a
solid B grade with a thoroughly-documented ceiling. Full writeup:
[docs/DGA_MODEL_ROADMAP.md](DGA_MODEL_ROADMAP.md#phase-6--small-ensemble-of-the-proven-cnn-only-architecture-investigated-not-shipped).

---

## What "10/10" actually means, concretely

Not a bigger model, again — a system where:
1. 🟡 Every detection category the platform claims to have has been
   checked against real attack data at least once — 5 of 6 now (DGA,
   flow anomaly, and all 4 rules, now that DDoS/C2/exfil are fixed and
   validated too). JA4 was investigated for real TWICE, independently
   (real `ja4plus` extraction against the real Lumma pcap, then again
   against 9 real CTU-13 botnet pcaps spanning two genuinely unrelated
   malware families) and found not viable both times, for the same
   well-understood reason (Phase 10.8) — a real, disclosed, now
   twice-confirmed negative result, not an unchecked gap; still no
   working rule (Phase 6, Phase 10.8).
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
   (53.0% vs. 52.6% recall for the best single detector, now across all
   seven detectors including the windowed DDoS-rate/C2-periodicity/
   exfil-byte-volume trio), not just a reshuffled number (Phase 8, later
   re-measured after Phase 10.5's flow-autoencoder retrain).
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

Phases 5, 7, 8, 9, and 10 are done (6 partially — Reconnaissance, DDoS,
C2 Beaconing, and Data Exfiltration are all done; JA4 fingerprinting was
genuinely investigated against real captured malware traffic and found
not viable this way, a real negative result rather than an unstarted
task). What's left is narrow: a real, broadly-curated malicious JA4 feed
(Abuse.ch or similar) would be needed to try again properly, and even
then may not catch this specific malware family.
