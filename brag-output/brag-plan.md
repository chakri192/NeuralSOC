# Brag Plan: NeuralSOC

## What is this app?

NeuralSOC is a real-time ML-powered threat detection platform built for networks with hardware data diodes — where the link is physically one-way, so the system can *see* everything and *write back* nothing.

## The angle

The constraint IS the product. Every other security tool assumes it can push back. NeuralSOC's entire existence is a bet that passively watching — with a CNN classifier, a flow autoencoder, correlated incidents, and an ATT&CK-mapped kill chain — is enough to catch them. The punchline: it is.

Open on the constraint. Close on the catch.

## Hook (first 2–3 seconds)

Black screen. One line types out, character by character, with key sounds:

> **"One-way link. No write-back. Ever."**

The cursor blinks once. Hard cut.

## Key moments (the middle)

- **The incident queue materialises** — matte-black dashboard, 5 KPI cards slam in one by one: `Needs Triage`, `Critical`, `High`, `Total Active`, `Avg Risk Score`. Numbers are all non-zero and alarming.
- **A CRITICAL row is selected** — the risk progress bar fills red. The detail panel opens below. Tabs: Summary · Kill Chain · Evidence · ATT&CK Mapping. The Kill Chain tab is active; MITRE tactic labels cascade down: *Initial Access → Discovery → Command and Control → Exfiltration*.
- **The threat class badge** — close shot of the severity badge: `CRITICAL · DGA / DNS Tunnelling · T1568.002`. Confidence score: `0.95`. Model: `CNN Classifier`.

## Outro / punchline

Logo and product name centre-frame. One line below it:

> **"Passive. Precise. Paranoid."**

Beat. Fade.

## User flow worth showing

1. **Entry** — threat alert arrives from the one-way sensor pipeline; appears in the incident queue with a risk score and severity badge.
2. **Key action** — analyst clicks the CRITICAL row; detail panel opens showing Kill Chain → ATT&CK Mapping tabs.
3. **Result** — analyst hits "Confirm & Escalate". Toast: `✓ Confirmed and escalated`.

## Tone

- **Preset:** `cinematic`
- **Creative direction:** Quiet, confident, military-grade ops footage energy. No startup energy. No jokes. Every frame earns its place.
- **Interpretation:** Slow reveals, big text, dramatic holds. Motion is deliberate. The product's own matte-black palette does the atmosphere work. Sound is restrained — one deep bell at the reveal, fade on the outro.

## Format: landscape — 1920×1080
## Duration: 20 seconds

## Visual identity (from the project)

- **Background:** `#0a0a0a` (true matte black)
- **Surface:** `#131313`
- **Accent:** `#3b82f6` (electric blue)
- **Critical:** `#e5484d` (threat red)
- **High:** `#f5a524` (amber)
- **Text:** `#eeeeee`
- **Text muted:** `#94948f`
- **Display font:** `Inter` (ui font from theme.py)
- **Mono font:** `JetBrains Mono` (used for IDs, IPs, alert codes)
- **Strongest visual element:** The KPI strip + incident queue table with severity colour coding and the risk progress bar filling red

## Share copy (draft)

We built NeuralSOC for networks that physically can't write back. The threats still get caught.

---

## Audio direction

- **Role:** Cinematic support — the music creates tension and gravitas, SFX punctuate the reveals
- **Music:** `happy-beats-business-moves-vol-12-by-ende-dot-app.mp3` (steady and clean, best for cinematic)
- **Music treatment:** Start at 0s, volume 0.32. Fade slightly under the outro text. No upbeat energy — this track is the quietest, most controlled of the set.
- **Music cue guidance:** Bundled preset at `<skill-dir>/assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.json`. Strong cues: 8.74s (0.99), 13.11s (0.98), 17.47s (0.99). Target: KPI cards slam at ~8.74s (beat-locked), Kill Chain reveal at ~13.11s (beat-locked), Confirm toast at ~17.47s (beat-locked).
- **Audio-reactive treatment:** Subtle. Use music RMS/bass to make the dashboard surface glow and the critical badge presence breathe gently. No waveform or equalizer visuals.
- **SFX posture:** Sparse / cinematic. 3 SFX total — not more.
- **Audio-coupled moments:**
  - Hook line types out → `keyboard/keypress-*.wav` randomised per character (subtle, low volume)
  - KPI cards slam in → `impact/impactSoft_medium_001.ogg` on the 5th card landing
  - Confirm & Escalate toast → `impact/impactBell_heavy_000.ogg` (the payoff)
- **Restraint rule:** No glitch sounds. No punch. No casino. This is not chaotic — it is precise.

---

## Storyboard

### Scene 1 — Hook — 3.5s

**On screen:** Pure `#0a0a0a` black. A monospace cursor blinks once (JetBrains Mono, `#3b82f6` accent). Then the line types out character by character:

> `One-way link. No write-back. Ever.`

Text is centred, large (56px), `#eeeeee`. Each character arrives with a randomised soft keypress sound. Cursor blinks at the end. Line is fully settled for ~1.5s.

Sequential/interaction: yes — character-by-character type-out, ~22 characters, ~0.08s per character, completes by 2.0s, holds until 3.5s.
Audio intent: quiet, precise, slightly menacing — the constraint stated as fact.
Audio-coupled idea: keypress-*.wav randomised per character at low volume (0.35).
Music: low vol-12 bed fades in under the typing.
Transition mood: hard cut → Scene 2

---

### Scene 2 — Dashboard materialises — 5s

**On screen:** The full T-SOC Operations Center dashboard renders in. Dark `#131313` surface. The top KPI strip appears: 5 cards slam in one by one from left to right with a short pop:

1. `Needs Triage` — `14` (accent blue)
2. `Critical` — `7` (threat red `#e5484d`)
3. `High` — `12` (amber `#f5a524`)
4. `Total Active` — `31`
5. `Avg Risk Score` — `82`

Below: the incident queue table is visible. Several rows. The top row is severity CRITICAL, risk bar filling red.

The sidebar shows: `T-SOC` logo, `analyst@demo.com`, `ENV: DEMO · DIODE: ONE-WAY`.

Sequential/interaction: yes — 5 KPI cards arrive one by one, ~0.4s apart. Beat-locked: first card at ~5.0s, last card lands at ~6.6s, near the beat at 6.56s.
Audio intent: builds tension — the scope of the threat becomes clear with each card.
Audio-coupled idea: `impactSoft_medium_001.ogg` on the 5th card landing (~6.6s, beat-locked to 6.56s).
Music: vol-12 bed, full presence now.
Transition mood: soft crossfade → Scene 3

---

### Scene 3 — Kill Chain — 6s

**On screen:** An incident row is clicked. Risk bar at 100%, severity badge `CRITICAL`. The detail panel opens below. The Kill Chain tab is active. MITRE tactic phases cascade down in sequence, each one appearing as a row with its label and technique code:

1. `Initial Access` — T1046 (Reconnaissance)
2. `Command and Control` — T1568.002 (DGA / DNS Tunnelling)
3. `Command and Control` — T1071.001 (Encrypted Traffic Malware)
4. `Exfiltration` — T1048

Below each: the alert timestamp and confidence score in mono. `CNN Classifier · 0.95`.

Sequential/interaction: yes — 4 Kill Chain rows arrive one by one, ~0.7s apart. Beat-grid snap: near beats 13.11s, 13.64s, 14.20s, 14.73s.
Audio intent: each entry is a new finding — the music should feel like gathering dossier pages.
Audio-coupled idea: `interface/drop_001.ogg` on each phase arrival at low volume (0.45) — or silence after first; Hyperframes' call.
Music: vol-12 bed, steady.
Transition mood: clean crossfade → Scene 4

---

### Scene 4 — Confirm & Escalate — 3s

**On screen:** The analyst actions tab. Three buttons: `Acknowledge` | `Mark False Positive` | `Confirm & Escalate`. A simulated cursor moves to `Confirm & Escalate` (primary blue button). Click. Toast notification slides in from the top right:

> `✓ Confirmed and escalated: INC-10-0-0-5`

Beat. Toast sits for ~1s. Beat-locked to strong cue at ~17.47s.

Sequential/interaction: yes — cursor moves, click, toast appears.
Audio intent: resolution — the job is done.
Audio-coupled idea: `impact/impactBell_heavy_000.ogg` at the moment the toast appears (~17.5s, beat-locked 17.47s) at volume 0.75.
Simulated interaction: `ui/mouseclick1.ogg` when cursor clicks the button.
Music: vol-12 bed, begin gentle fade.
Transition mood: soft crossfade → Scene 5

---

### Scene 5 — Outro — 2.5s

**On screen:** Back to `#0a0a0a`. Centre-frame: the T-SOC shield logo (brand.svg) fades in, then below it:

> **NeuralSOC**

One line beneath:

> `Passive. Precise. Paranoid.`

Both lines are Inter, `#eeeeee`. Logo subtle glow (audio-reactive to RMS). Music fades to silence by end.

Sequential/interaction: none — clean fade-in hold.
Audio intent: final breath — confidence, not celebration.
Audio-coupled idea: none. Let the bell from Scene 4 ring out.
Music: vol-12 fade to 0 by 20s.
Transition mood: fade to black

---

**Total duration: 3.5 + 5 + 6 + 3 + 2.5 = 20 seconds ✓**

**Music mood for this video:** Cinematic, steady, controlled — the restraint matches the platform's own constraint.
**Audio summary:** Quiet menace on the hook, building tension through the KPI reveal, a decisive bell payoff on the escalation, then silence under the logo.
