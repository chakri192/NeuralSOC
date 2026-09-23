# Hyperframes Composition Brief: NeuralSOC (T-SOC)

## Objective
Create a short launch-style brag video for NeuralSOC, a data-diode network
threat-detection platform.

## Output
- Composition directory: `brag-output-2026-09-23-231016/composition/`
- Rendered video: `brag-output-2026-09-23-231016/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20s

## Source Material
- Project root: `/Users/chakri/Downloads/hackaton/project`
- Primary files read: `README.md`, `dashboard/theme.py`, `dashboard/styles/app.css`,
  `dashboard/pages/command_center.py`, `dashboard/components/ui.py`
- Product name: NeuralSOC (T-SOC)
- Tagline / strongest claim: it never writes back to the monitored network
  (hardware data-diode), and its detection numbers are measured against
  real captured botnet traffic (98.3% composite precision)
- Key UI or visual moment to recreate: the Kill Chain vertical timeline
  (`render_kill_chain` in `dashboard/components/ui.py`) condensing raw
  alerts into readable attack phases
- Copy that must appear verbatim:
  - "It can't write back to your network."
  - "That's not a limitation. That's the point."
  - "98.3%"
  - "precision — real botnet traffic, not synthetic"
  - "NeuralSOC"
  - "Passive. Precise. Paranoid."

## Creative Direction
- Tone preset: polished
- Creative direction: quiet command-center confidence — a security tool
  that earns trust by refusing to oversell
- Interpretation: 4 scenes, longer holds, soft crossfades, no bounce/flash,
  nothing arrives faster than it can be read
- Angle: most security products sell "AI-powered, unstoppable." This one's
  differentiator is restraint — a diode that physically cannot talk back,
  and a precision number that's a real measured figure, not a round
  marketing claim. Show the actual command-center UI working, especially
  the kill-chain timeline, rather than describing features.
- Hook: "It can't write back to your network." / "That's not a
  limitation. That's the point."
- Outro / punchline: "NeuralSOC" / "Passive. Precise. Paranoid."
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign
  - Any claim not grounded in this project's real, measured behavior
    (e.g. do not depict JA4 fingerprinting as an active detector — it was
    investigated and is a disclosed negative result, no rule is deployed)

## Visual Identity
- Background: #0a0a0a
- Text: #eeeeee (muted: #94948f)
- Accent: #3b82f6
- Severity accents: critical #e5484d, high #f5a524, medium #f5d90a
- Display font: Inter (400/500/600/700/800)
- Body/data font: JetBrains Mono (400/500/700)
- Visual references from the project: dashboard/theme.py's PALETTE (exact
  hex values above), dashboard/styles/app.css's `.tsoc-chain` kill-chain
  stepper (dot + connecting line + phase card), the Incident Queue's
  severity-colored table and KPI strip

## Storyboard
Use the storyboard in `brag-plan.md` as the creative contract.

Scene summary:
1. Hook — 3.5s — "It can't write back to your network." types on, then
   "That's not a limitation. That's the point." fades in beneath.
2. Command-center reveal — 5.24s — 3 KPI cards arrive left-to-right
   (Needs Triage / Critical / High), then 3 severity-colored incident
   rows slide in top-to-bottom.
3. Kill Chain — 7.0s — an opened incident's Kill Chain tab: phase 1
   ("Anomalous Flow × 37", amber dot) arrives, hold, then phase 2
   ("Data Exfiltration × 63", red dot, with a MITRE tag) arrives
   beat-locked; both hold together to scene end.
4. Number + outro — 4.26s — "98.3%" counts up, subtext "precision — real
   botnet traffic, not synthetic" settles, crossfade to "NeuralSOC" /
   "Passive. Precise. Paranoid." on black.

## Audio
- Audio role: sparse professional accents
- Audio arc: a low, flat synth bed under the whole video, a very slight
  lift under the kill-chain scene, fading out under the outro card
- Music: `happy-beats-business-moves-vol-12-by-ende-dot-app.mp3`
  (109.96 BPM, bundled cue preset available)
- Music treatment: volume ~0.30, enters flat at 0s, holds, subtle
  presence lift (not a swell) under scene 3, fades to 0 over the last ~2s
- Music cue guidance: bundled preset at
  `<skill-dir>/assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.json`.
  Strong cues used: 8.74s (0.99, scene 2→3 transition), 13.11s (0.98,
  kill-chain phase 2 reveal), 17.47s (0.99, number landing). Scene
  boundaries were shifted slightly (from the plan's round numbers) to
  land on these three strong cues; total duration stays 20s.
- Audio-reactive treatment: subtle — accent glow on the KPI numbers and
  kill-chain dots may breathe faintly with music RMS; no waveform/EQ
  visuals
- Audio-coupled moments:
  - Scene 1 — 2 quiet keyboard ticks under the hook line's type-in only
    (not the second line)
  - Scene 3 — one soft reveal cue exactly as kill-chain phase 2 lights up
    (beat-locked 13.11s); phase 1 arrives in silence
  - Scene 4 — one dry, deep accent exactly as "98.3%" settles on its
    final value (beat-locked 17.47s); no sound on the subtext or outro
    card
- SFX selection guidance: `interface/keypress-*.wav` for the hook ticks
  (two distinct files, not the same one twice), `interface/drop_001.ogg`
  for the kill-chain phase-2 reveal (gentle, not a hard hit), one
  `interface/bong_001.ogg` for the number landing (deep, used once,
  matches "polished" guidance of reserving it for a single accent)
- SFX analysis guidance: `<skill-dir>/assets/sfx/sfx-analysis.md` — prefer
  low/medium HF-risk files for these repeated, polished moments
- Exact SFX choice: chosen above from the approved library; volumes set
  low (ticks ~0.22, drop ~0.5, bong ~0.55) per polished-tone restraint
- Audio files: copied into `composition/assets/` before composition

## Hyperframes Instructions
Load the composition-building Hyperframes domain skills — `hyperframes-core`
(composition contract + `data-*` timing), `hyperframes-animation` (motion),
`hyperframes-creative` (design spec, beats, audio-reactive), `hyperframes-keyframes`
(seek-safe keyframes), and `hyperframes-cli` (lint/check/render) — if available
in this environment. /brag is its own workflow: do not enter the `hyperframes`
entry-point intent interview and do not route into its generic promo /
launch-video workflow. Prefer native Hyperframes conventions over anything
in `/brag`.

Requirements:
- Show at least one real UI, copy, or visual element from the source project
  (the Kill Chain timeline and the Incident Queue, both real dashboard
  components built this project).
- Keep all text readable in the final render.
- Keep the video within 15-25 seconds (target 20s).
- Include the planned music/SFX layer.
- Treat the beat-locked timestamps above as targets, not fixed law — shift
  within ±0.15s (major reveals) / ±0.10s (small entrances) if it improves
  readability or pacing.
- Use SFX to support motion: gentle reveal sound for the kill-chain card,
  one deep accent for the number landing, quiet key ticks for the type-in.
- When rendering, run the check/lint gate before render.
