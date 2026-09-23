# Hyperframes Composition Brief: NeuralSOC

## Objective

Create a 20-second cinematic launch video for NeuralSOC — a real-time ML threat detection platform built for networks with hardware data diodes. The constraint (one-way, no write-back) is the product's defining truth. The video opens on that constraint, shows the working dashboard, and closes with the analyst confirming the catch.

## Output

- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920×1080
- Duration: 20 seconds

## Source Material

- Project root: `/Users/chakri/Downloads/hackaton/project`
- Primary files read: `README.md`, `dashboard/theme.py`, `dashboard/app.py`, `dashboard/pages/command_center.py`, `dashboard/pages/investigate.py`, `dashboard/assets/brand.svg`
- Product name: **NeuralSOC** (marketed as T-SOC — Threat SOC)
- Tagline / strongest claim: **"One-way link. No write-back. Ever."** (the data-diode constraint, stated in the product's own sidebar text: `ENV: DEMO · DIODE: ONE-WAY`)
- Key UI to recreate: The Command Center — KPI strip + incident queue + incident detail panel with Kill Chain tab
- Copy that must appear verbatim:
  - `One-way link. No write-back. Ever.`
  - `ENV: DEMO · DIODE: ONE-WAY`
  - `Passive. Precise. Paranoid.`
  - `Confirmed and escalated: INC-10-0-0-5`

## Creative Direction

- **Tone preset:** `cinematic`
- **Creative direction:** Quiet, confident, military-grade ops footage energy. No startup hype. No jokes. Restraint is the aesthetic.
- **Interpretation:** Deliberate motion, dramatic holds, big text. The product's matte-black palette does the atmosphere work; the composition adds depth not decoration. Sound is sparse and intentional — three cues, not twenty.
- **Angle:** The constraint IS the product. Every other security tool assumes write-back. NeuralSOC doesn't. The punchline is that it still catches everything.
- **Hook:** Black screen. Monospace cursor blinks. Text types out character by character: `One-way link. No write-back. Ever.`
- **Outro / punchline:** Shield logo fades in, then: `NeuralSOC` / `Passive. Precise. Paranoid.`
- **Avoid:**
  - Generic SaaS language ("streamline", "all-in-one", "next-gen")
  - Abstract motion graphic filler
  - Upbeat startup energy
  - Any content resembling real credentials, IPs, or internal hostnames (use fictional: `10.0.0.5`, `demo.tsoc.local`)

## Visual Identity

- **Background:** `#0a0a0a` (true matte black — not navy, not charcoal)
- **Surface:** `#131313`
- **Surface raised:** `#1a1a1a`
- **Border:** `#2a2a2a`
- **Text:** `#eeeeee`
- **Text muted:** `#94948f`
- **Accent (blue):** `#3b82f6`
- **Critical (red):** `#e5484d`
- **High (amber):** `#f5a524`
- **Medium (yellow):** `#f5d90a`
- **Display font:** `Inter` (Google Font — load via CDN or system fallback)
- **Mono font:** `JetBrains Mono` (for IDs, IPs, alert codes, the hook line)
- **Visual references:** Matte-black dashboard surface, electric-blue accent for numbers, critical-red severity badges, risk progress bar filling red, JetBrains Mono for all technical identifiers

## Storyboard

Scene summary:
1. **Hook** — 3.5s — `One-way link. No write-back. Ever.` types out on black. Hold.
2. **Dashboard materialises** — 5s — KPI cards slam in one by one (14 / 7 / 12 / 31 / 82). Incident queue table visible below. CRITICAL row prominent.
3. **Kill Chain** — 6s — CRITICAL row clicked. Detail panel opens. Kill Chain tab active. 4 MITRE phases cascade in one by one: Reconnaissance → DGA/DNS Tunnelling → Encrypted Traffic → Exfiltration.
4. **Confirm & Escalate** — 3s — Analyst Actions tab. Cursor moves to `Confirm & Escalate`. Click. Toast: `✓ Confirmed and escalated: INC-10-0-0-5`.
5. **Outro** — 2.5s — `#0a0a0a`. Shield logo fades in. `NeuralSOC`. `Passive. Precise. Paranoid.` Music fades.

## Audio

- **Audio role:** Cinematic support — music creates gravitas, SFX punctuate three key moments only
- **Audio arc:** Quiet typing ambience → building tension as KPI cards arrive → steady presence through Kill Chain → decisive bell at escalation → silence under logo
- **Music:** `assets/music/happy-beats-business-moves-vol-12-by-ende-dot-app.mp3`
- **Music treatment:** Start at 0s, `data-volume="0.32"`. Fade to 0 by 20s. Do not upbeat-emphasise — this track is the controlled, steady option. Let it be background, not feature.
- **Music cue guidance:** Bundled preset at `<skill-dir>/assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.json`. Strong cues in 0–20s window: **8.74s (0.99)**, **13.11s (0.98)**, **17.47s (0.99)**. Beat grid ~109.96 BPM (~0.545s/beat). Use these for beat-locking: KPI 5th card near 8.74s, Kill Chain phase 1 reveal near 13.11s, Confirm & Escalate toast near 17.47s.
- **Audio-reactive treatment:** Subtle. Use music RMS/bass to make the `#0a0a0a` background gain a barely-perceptible warmth/depth, and to let the `#e5484d` critical badge glow pulse gently. No waveform bars, no equalizer visuals, no text scaling.
- **Audio-coupled moments:**
  - Scene 1 (Hook typing) — `keyboard/keypress-*.wav` randomised per character at `data-volume="0.35"`. ~22 characters.
  - Scene 2 (5th KPI card lands at ~8.74s) — `impact/impactSoft_medium_001.ogg` at `data-volume="0.70"`, beat-locked to 8.74s
  - Scene 4 (Toast appears at ~17.47s) — `impact/impactBell_heavy_000.ogg` at `data-volume="0.75"`, beat-locked to 17.47s. Let it ring out through the outro.
  - Scene 4 (Cursor click) — `ui/mouseclick1.ogg` at `data-volume="0.65"` when the button registers
- **SFX selection guidance:** Three families only: `keyboard/`, `impact/`, `ui/`. No casino, no glitch, no punch. Every SFX should feel like it belongs to a precision instrument, not an app demo.
- **SFX analysis guidance:** Use `<skill-dir>/assets/sfx/sfx-analysis.md` — prefer low/medium HF-risk files for this tone.
- **Exact SFX choice:** Hyperframes selects exact filenames, timestamps, and volumes from the implemented animation.
- **Audio files:** Copy music and chosen SFX into `brag-output/composition/assets/` before build.

## Hyperframes Instructions

Load `hyperframes-core`, `hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`, `hyperframes-cli`. Do not enter the generic `hyperframes` intent interview. `/brag` owns the creative brief; Hyperframes owns implementation.

**Requirements:**
- Show the real dashboard UI: KPI strip, incident queue, Kill Chain tab, triage button — all on the `#0a0a0a` surface with the exact colour palette above.
- The hook line must be in JetBrains Mono, centred, large (48–64px), electric blue accent cursor.
- KPI cards must arrive sequentially left-to-right. The `Critical: 7` card must show in `#e5484d`.
- Kill Chain MITRE phases must arrive sequentially, each line showing tactic name + technique code in `JetBrains Mono`.
- The cursor-clicks-button interaction must be visible and simulated (not implied).
- Keep all text readable — reading-time floors apply (short label: 0.8s settled; sentence: 0.3s/word min 1.2s). The hook line must hold fully visible for ≥1.5s after typing completes.
- Total duration: exactly 20 seconds.
- Audio-reactive glow on the critical badge and background depth — subtle, not strobing.
- Beat-lock the three major moments: KPI 5th card (~8.74s), Kill Chain reveal (~13.11s), Escalation toast (~17.47s). Mark each with `// beat-locked`.
- Kill Chain phases snap to consecutive beat-grid points near 13.11s: ~13.11s, ~13.64s, ~14.20s, ~14.73s. Mark with `// beat-grid`.
- `hyperframes check` must pass with zero errors before render.
