# Brag Plan: NeuralSOC (T-SOC)

## What is this app?
A real-time network threat-detection platform built around a hardware
data-diode: it physically cannot write back to the network it's watching,
and it's validated against real captured botnet traffic instead of
synthetic data.

## The angle
Most security products sell "AI-powered, unstoppable." This one's pitch is
the opposite: it can't talk back to your network (the diode is one-way by
construction), and it doesn't oversell what it catches — it's benchmarked
against real botnet traffic, and the number it leads with (98.3%) is a real,
measured precision figure, not a marketing round number. Restraint is the
joke and the credibility play at once. Show the actual command-center UI
doing real work — the kill-chain timeline especially — rather than
describing features.

## Hook (first 2-3 seconds)
Matte-black frame. White type, center, types on in one clean beat:
"It can't write back to your network." Beat. Second line drops in under it,
smaller: "That's not a limitation. That's the point."

## Key moments (the middle)
- The Incident Queue: KPI strip counts in (Needs Triage / Critical / High),
  then the severity-colored incident table populates row by row — the real
  command-center visual, not a mockup.
- The Kill Chain tab: open a real incident, watch the vertical timeline
  build itself phase by phase — a dot lights up, the connecting line draws
  down, "Anomalous Flow × 37" slides in, then "Data Exfiltration × 63"
  with its MITRE tag. Raw alerts condensing into a readable attack story,
  live.
- The number: "98.3%" counts up under a single line — "precision, against
  real botnet traffic" — landing the credibility claim with the same
  restraint as everything before it.

## Outro / punchline
Cut to logo mark and wordmark on black. Tagline beneath, small, monospace:
"Passive. Precise. Paranoid." Hold. Cut to black.

## User flow worth showing
Login → Incident Queue (severity-sorted, KPI strip live) → open an incident
→ Kill Chain tab reveals the condensed attack-phase timeline. This is the
centerpiece: the product's newest real feature, doing real work, not a
landing-page recreation.

## Tone
- Preset: polished
- Creative direction: quiet command-center confidence — a security tool
  that earns trust by refusing to oversell
- Interpretation: 4 scenes, longer holds, soft crossfades. Type moves in
  clean and settles — no bounce, no flash. Confidence reads through
  restraint: nothing arrives faster than it can be read, nothing repeats
  for emphasis it hasn't earned.

## Format: landscape — 1920x1080
## Duration: 20s

## Visual identity (from the project)
- Background: #0a0a0a (matte black, dashboard/theme.py PALETTE["bg"])
- Accent: #3b82f6 (dashboard/theme.py PALETTE["accent"])
- Text: #eeeeee (PALETTE["text"]) / muted: #94948f (PALETTE["text-muted"])
- Severity accents: critical #e5484d, high #f5a524, medium #f5d90a
- Display font: Inter (bold, for headline type)
- Data/mono font: JetBrains Mono (for stats, counts, MITRE tags — matches
  the real dashboard's own `--font-mono` treatment)
- Strongest visual element: the Kill Chain vertical timeline stepper
  (dot + connecting line + phase card, dashboard/components/ui.py's
  `render_kill_chain`, styled via `.tsoc-chain` in dashboard/styles/app.css)

## Share copy (draft)
Built a SOC platform that physically can't write back to the network it's
watching — 98.3% precision against real botnet traffic. Passive. Precise.
Paranoid.

## Audio direction
- Role: sparse professional accents
- Music: low, moody tech/synth bed — minimal percussion, no build-to-drop;
  quiet confidence, not tension
- Music treatment: enters low under the hook, holds flat through the
  dashboard reveal, a very subtle lift under the kill-chain scene (nothing
  close to a swell), settles and fades under the outro
- Music cue guidance: to be detected at composition time (no bundled
  preset assumed). Target strong-cue alignment near 0s (hook type-in),
  ~8s (kill-chain scene start), ~15s (98.3% landing). No dense beat-grid
  needed — only two sequential reveals in the whole video (the two
  kill-chain phase cards), both should land clean rather than snapped to
  a fast beat-grid.
- Audio-reactive treatment: subtle — the accent glow around KPI numbers
  and the kill-chain dots may breathe faintly with music energy; nothing
  waveform-shaped or flashy
- SFX posture: sparse, motion-matched, professional restraint — at most
  4 discrete hits in the whole video
- Audio-coupled moments: hook line typing in (very quiet key ticks, 2-3
  max), the two kill-chain phase-card arrivals (one soft confirm-blip
  each), the 98.3% count-up landing (one low, dry hit — no whoosh)
- Restraint rule: no trailer-style swell, no dense rhythmic layer, nothing
  louder than the moment's own text is readable over

## Storyboard

### Scene 1 — Hook — 3.5s
Matte-black frame. "It can't write back to your network." types on in one
clean beat, centered, Inter bold, full width restraint (not oversized).
Holds ~1.3s fully settled. Second line drops in beneath, smaller, muted
text color: "That's not a limitation. That's the point." Holds ~1s.
Sequential/interaction: yes — line 1 types in, line 2 fades in under it
after line 1 settles (two arrivals, not simultaneous).
Audio intent: quiet, deliberate, almost clinical — this is a statement,
not a pitch.
Audio-coupled idea: subtle key-tick texture under line 1's type-in only;
line 2 is a plain fade, no ticks.
Music: low synth bed enters here, flat and quiet.
Transition mood: soft crossfade → Scene 2

### Scene 2 — Command center reveal — 5s
Cut to the real Incident Queue UI on the matte-black dashboard background.
KPI strip counts in left to right: "Needs Triage", "Critical", "High" —
each number ticking up briefly before settling. Then the severity-colored
incident table populates, three rows sliding in top to bottom, each row's
severity badge in its real color (critical red / high orange / medium
yellow).
Sequential/interaction: yes — 3 KPI cards arrive left-to-right (~0.4s
apart), then 3 table rows slide in top-to-bottom (~0.4s apart) once the
KPI strip settles.
Audio intent: the pipeline is alive and working — brisk but not urgent.
Audio-coupled idea: each KPI card and each table row gets a very soft,
low-volume UI tick on arrival (motion-matched, not musical).
Music: bed continues, unchanged.
Transition mood: clean wipe → Scene 3

### Scene 3 — Kill Chain — 7s
Cut to an opened incident's Kill Chain tab. A vertical timeline builds
itself: first dot (amber, "Anomalous Flow") lights up, connecting line
draws downward, phase card slides in beside it reading "Anomalous Flow ×
37". Beat. Second dot (red, "Data Exfiltration") lights up below, phase
card slides in: "Data Exfiltration × 63", with a small MITRE tag beneath
it. Both cards fully settled and readable together at scene end.
Sequential/interaction: yes — dot 1 lights + line draws + card 1 arrives,
hold ~1.5s, then dot 2 lights + card 2 arrives, hold ~2s with both visible.
Audio intent: this is the "wow, that's real" beat — still restrained, but
the one moment allowed a flicker more presence.
Audio-coupled idea: one soft confirm-blip exactly as each dot lights up
(2 total). Music lifts very slightly under this scene only.
Music: subtle lift, still low in the mix.
Transition mood: soft crossfade → Scene 4

### Scene 4 — Number + outro — 4.5s
Cut to black. "98.3%" counts up cleanly (not a slot-machine spin — a
fast, clean count landing on the final value), Inter bold, large but not
screen-filling. Beneath it, JetBrains Mono, smaller: "precision — real
botnet traffic, not synthetic." Hold ~1.3s. Crossfade to logo mark +
wordmark, tagline beneath in muted JetBrains Mono: "Passive. Precise.
Paranoid." Hold to end.
Sequential/interaction: yes — number counts up then settles, subtext
fades in after it settles (not simultaneous), then crossfades to the
outro card as a separate beat.
Audio intent: one dry, confident landing — then quiet.
Audio-coupled idea: single low hit exactly as "98.3%" settles on its
final value. No sound on the subtext or the outro card — let it go quiet.
Music: fades out under the outro card.
Transition mood: soft crossfade → end

**Music mood for this video:** polished / low-key tech-cinematic, no build
**Audio summary:** A quiet, confident bed that never swells — presence
comes from two sparse confirm-blips on the kill-chain reveal and one dry
low hit on the final number, with the mix intentionally going near-silent
under the outro card.
