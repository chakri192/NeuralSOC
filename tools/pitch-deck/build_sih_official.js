// SIH-2025-compliant restructure: same visual theme as
// NeuralSOC_Detailed_Pitch.pptx (navy/blue, card system, icon rows), but
// repaged into the 6 sections the official SIH2025-IDEA-Presentation-Format
// template requires, in order, within its 6-slide cap: Title Page, Idea
// Title, Technical Approach, Feasibility & Viability, Impact & Benefits,
// Research & References. Separate, standalone build -- does not touch
// NeuralSOC_Detailed_Pitch.pptx or any other deck.
const pptxgen = require('pptxgenjs');
const { iconPng } = require('./icons.js');

const C = {
  bg: 'FFFFFF',
  cardLight: 'F1F5F6',
  headlineNavy: '14264D',
  bodyGray: '5B5D61',
  accentBlue: '3B7DDB',
  accentBlueTint: 'E8F0FC',
  border: 'D9E0E3',
  critical: 'C0392B',
  high: 'D68910',
  good: '2E7D46',
  muted: '9AA3AC',
  // Sampled directly from the official SIH 2026 logo mark, so pages 3-5
  // carry the hackathon's own saffron/green instead of a generic tech blue.
  sihOrange: 'F48C22',
  sihOrangeTint: 'FDF0DF',
  sihGreen: '149447',
  sihGreenTint: 'E7F5EC',
};

const FONT_HEAD = 'Calibri';
const FONT_BODY = 'Calibri';
const FONT_MONO = 'Courier New';

async function main() {
  const icons = {};
  const iconNames = [
    'FiEye', 'FiShield', 'FiGitBranch', 'FiTarget', 'FiUsers', 'FiCheckCircle',
    'FiAlertTriangle', 'FiDatabase', 'FiLock', 'FiKey', 'FiFileText', 'FiActivity',
    'FiServer', 'FiBookOpen', 'FiCpu', 'FiWifi', 'FiClock', 'FiSliders',
    'FiLayers', 'FiZap', 'FiTrendingUp', 'FiRefreshCw', 'FiMonitor', 'FiSearch',
  ];
  for (const name of iconNames) {
    icons[name] = await iconPng(name, 'FFFFFF');
  }
  const ic = (name) => icons[name];

  const pres = new pptxgen();
  pres.layout = 'LAYOUT_WIDE';
  const W = 13.333, H = 7.5;
  const TOTAL = 5;

  function iconCircle(slide, { x, y, size = 0.5, icon, color = C.headlineNavy }) {
    slide.addShape('ellipse', { x, y, w: size, h: size, fill: { color }, line: { type: 'none' } });
    const pad = size * 0.26;
    slide.addImage({ data: ic(icon), x: x + pad, y: y + pad, w: size - 2 * pad, h: size - 2 * pad });
  }

  function eyebrow(slide, text, { x, y, w = 9 }) {
    slide.addText(text.toUpperCase(), {
      x, y, w, h: 0.3, isTextBox: true, margin: 0,
      fontFace: FONT_MONO, fontSize: 11, color: C.accentBlue, charSpacing: 2, bold: true,
    });
  }

  function pageNum(slide, n) {
    slide.addText(`${n} / ${TOTAL}`, {
      x: W - 1.0, y: H - 0.42, w: 0.8, h: 0.3, isTextBox: true, margin: 0,
      fontFace: FONT_MONO, fontSize: 9, color: C.bodyGray, align: 'right',
    });
  }

  const SIH_BLUE = '0070C0';

  // SIH 2026 branding, used identically on every slide -- team-name oval +
  // the real 2026 logo mark, downloaded from sih.gov.in/img1/SIH2026-logo.png
  // and cropped to just the SIH brain/bulb + wordmark (matching what the
  // original 2025 template used per-slide, not the full multi-agency
  // lockup), plus the original template's own footer convention: centered
  // caption, page number right, nothing else.
  function sihHeader(slide) {
    slide.addText('CIRCUMSPECT GATEWAY', { x: 0.6, y: 0.3, w: 1.75, h: 0.5, isTextBox: true, margin: 0, align: 'left', valign: 'middle', fontFace: FONT_MONO, fontSize: 11, bold: true, color: C.accentBlue, charSpacing: 2 });
    slide.addImage({ path: '/Users/chakri/Downloads/sih14-redesign/sih_logo_2026_mark.png', x: 10.99, y: 0.19, w: 2.04, h: 1.054 });
  }

  function sihFooter(slide, n) {
    slide.addShape('rect', { x: 0, y: 7.08, w: W, h: 0.42, fill: { color: SIH_BLUE }, line: { type: 'none' } });
    slide.addText('SIH 2026', { x: 0, y: 7.08, w: W - 1.0, h: 0.42, isTextBox: true, margin: 0, valign: 'middle', align: 'center', fontFace: FONT_BODY, fontSize: 10, color: 'FFFFFF' });
    slide.addText(`${n} / ${TOTAL}`, { x: W - 1.2, y: 7.08, w: 0.8, h: 0.42, isTextBox: true, margin: 0, valign: 'middle', align: 'right', fontFace: FONT_BODY, fontSize: 10, color: 'FFFFFF' });
  }

  function newSlide() {
    const s = pres.addSlide();
    s.background = { color: C.bg };
    return s;
  }

  function flowArrow(slide, { x, y, w, h = 0.08 }) {
    slide.addShape('rightArrow', { x, y: y - h / 2, w, h, fill: { color: C.accentBlue }, line: { type: 'none' } });
  }

  // ============================================================
  // PAGE 1 -- Idea Title / Proposed Solution
  // ============================================================
  {
    const s = newSlide();
    sihHeader(s);

    eyebrow(s, 'Idea Title · Proposed Solution', { x: 0.7, y: 0.95 });

    s.addText('Passive Observation.\nContextual Intelligence.', {
      x: 0.7, y: 1.2, w: 11.9, h: 0.9, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 26, bold: true, color: C.headlineNavy, lineSpacing: 30,
    });

    // --- Left: what the project actually is, in points -- not a paragraph.
    const expX = 0.7, expW = 6.7;
    s.addText('WHAT IS NEURALSOC', { x: expX, y: 2.25, w: expW, h: 0.24, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 9.5, bold: true, color: C.headlineNavy, charSpacing: 1.5 });
    const explain = [
      ['FiWifi', 'Passive, Real-Time Monitoring', 'Watches network traffic via TAP/SPAN — zero disruption to production systems.'],
      ['FiCpu', 'Seven Parallel Detectors', 'Rule-based and deep-learning models scan every connection at once.'],
      ['FiGitBranch', 'One Correlated Score, Not Scattered Alerts', 'Collapses up to 100 raw per-detector alerts into a single calibrated incident.'],
      ['FiSearch', 'Fully Explainable', 'Every incident is MITRE ATT&CK-mapped, with evidence an analyst can inspect.'],
      ['FiShield', 'Proven on Real Attacks', '98.3% precision, 1.15% FPR — measured against real CTU-13 botnet traffic, not synthetic data.'],
    ];
    let ey = 2.58;
    for (const [icon, title, body] of explain) {
      iconCircle(s, { x: expX, y: ey, size: 0.34, icon });
      s.addText(title, { x: expX + 0.48, y: ey - 0.02, w: expW - 0.48, h: 0.26, isTextBox: true, margin: 0, fontFace: FONT_HEAD, fontSize: 10.5, bold: true, color: C.headlineNavy });
      s.addText(body, { x: expX + 0.48, y: ey + 0.25, w: expW - 0.48, h: 0.42, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 8.5, color: C.bodyGray, lineSpacing: 11 });
      ey += 0.72;
    }

    // --- Right: a real video slot, sized and labeled so a judge finds it
    // immediately -- drop the actual recording in here in PowerPoint.
    const vX = 7.55, vW = 5.15;
    s.addText('WATCH THE DEMO', { x: vX, y: 2.25, w: vW, h: 0.24, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 9.5, bold: true, color: C.headlineNavy, charSpacing: 1.5 });
    const vfH = vW * 9 / 16, vfY = 2.55;
    s.addShape('roundRect', { x: vX, y: vfY, w: vW, h: vfH, rectRadius: 0.08, fill: { color: '000000' }, line: { type: 'none' } });
    s.addMedia({
      type: 'video',
      path: '/Users/chakri/Downloads/hackaton/project/neuralsoc-videos/composition_5min/renders/composition_5min_2026-09-29_00-49-32.mp4',
      x: vX, y: vfY, w: vW, h: vfH,
    });

    s.addText('Full walkthrough: passive capture → seven detectors → one correlated, explainable incident.', {
      x: vX, y: vfY + vfH + 0.16, w: vW, h: 0.42, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9, color: C.bodyGray, lineSpacing: 12,
    });
    s.addText([
      { text: '98.3% precision', options: { bold: true, color: C.accentBlue, fontSize: 9.5 } }, { text: '  ·  ', options: { color: C.border, fontSize: 9.5 } },
      { text: '7 detectors', options: { bold: true, color: C.accentBlue, fontSize: 9.5 } }, { text: '  ·  ', options: { color: C.border, fontSize: 9.5 } },
      { text: '1.15% FPR', options: { bold: true, color: C.accentBlue, fontSize: 9.5 } },
    ], { x: vX, y: vfY + vfH + 0.6, w: vW, h: 0.28, isTextBox: true, margin: 0 });

    // Three differentiator tags right under the stat line -- fills what was
    // dead space with scannable, real claims instead of a bigger empty card.
    const tags1 = ['Zero disruption', 'MITRE-mapped', 'Self-hosted'];
    let tgx = vX;
    for (const tag of tags1) {
      const tw = 0.28 + tag.length * 0.074;
      s.addShape('roundRect', { x: tgx, y: vfY + vfH + 0.92, w: tw, h: 0.32, rectRadius: 0.16, fill: { color: C.accentBlueTint }, line: { type: 'none' } });
      s.addText(tag, { x: tgx, y: vfY + vfH + 0.92, w: tw, h: 0.32, isTextBox: true, margin: 0, align: 'center', valign: 'middle', fontFace: FONT_MONO, fontSize: 8, color: C.accentBlue, bold: true });
      tgx += tw + 0.14;
    }

    // Adobe Acrobat/Reader gates embedded video behind a one-time "trust
    // this document" prompt (its own security setting, not fixable from
    // the file side) -- a plain note here beats a judge assuming it's
    // broken and moving on.
    s.addText([
      { text: 'Note for judges: ', options: { bold: true } },
      { text: 'video not playing? Click “Trust this document” in Adobe Acrobat.', options: {} },
    ], {
      x: vX, y: vfY + vfH + 1.26, w: vW, h: 0.36, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, italic: true, color: C.bodyGray, lineSpacing: 12,
    });

    // Left column closes on the same line the video itself closes on, so
    // the deck and the walkthrough land on the same note.
    s.addText('Built for the institutions that can’t afford to just guess — schools, hospitals, and government networks.', {
      x: expX, y: 6.28, w: expW, h: 0.5, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9, italic: true, color: C.bodyGray, lineSpacing: 12.5,
    });

    sihFooter(s, 1);
  }

  // ============================================================
  // PAGE 2 -- Technical Approach
  // ============================================================
  {
    const s = newSlide();
    sihHeader(s);
    eyebrow(s, 'Technical Approach', { x: 0.7, y: 0.95 });
    s.addText('A four-stage pipeline, seven parallel detectors.', {
      x: 0.7, y: 1.25, w: 11.9, h: 0.5, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 25, bold: true, color: C.headlineNavy,
    });

    s.addText('METHODOLOGY & PROCESS', { x: 0.7, y: 1.9, w: 6, h: 0.24, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 10.5, bold: true, color: C.headlineNavy, charSpacing: 1.5 });

    const stages = [
      { title: '1. Ingest', icon: 'FiWifi', items: ['Zeek — passive TAP/SPAN', 'Redpanda / Kafka streams', 'Lossless packet mirroring'] },
      { title: '2. Detect', icon: 'FiCpu', items: ['7 parallel detectors', 'Rules + PyTorch models', 'Faust stream workers'] },
      { title: '3. Correlate', icon: 'FiGitBranch', items: ['Redis-backed windowing', 'Composite risk score', 'Evidence-linked scoring'] },
      { title: '4. Present', icon: 'FiMonitor', items: ['PostgreSQL', 'FastAPI → Streamlit', 'Kill Chain + MITRE view'] },
    ];
    const pcw = 2.7875, pcgap = 0.25, pcy = 2.2, pch = 2.4;
    let pcx = 0.7;
    stages.forEach((st, idx) => {
      s.addShape('roundRect', { x: pcx, y: pcy, w: pcw, h: pch, rectRadius: 0.08, fill: { color: C.cardLight }, line: { type: 'none' } });
      iconCircle(s, { x: pcx + 0.25, y: pcy + 0.25, size: 0.5, icon: st.icon });
      s.addText(st.title, { x: pcx + 0.88, y: pcy + 0.22, w: pcw - 1.13, h: 0.5, isTextBox: true, margin: 0, valign: 'middle', fontFace: FONT_HEAD, fontSize: 14.5, bold: true, color: C.headlineNavy });
      let iy = pcy + 0.98;
      for (const it of st.items) {
        s.addText([{ text: '→  ', options: { color: C.accentBlue, bold: true } }, { text: it, options: { color: C.bodyGray } }], {
          x: pcx + 0.22, y: iy, w: pcw - 0.44, h: 0.32, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, lineSpacing: 12,
        });
        iy += 0.4;
      }
      if (idx < stages.length - 1) {
        flowArrow(s, { x: pcx + pcw + pcgap * 0.25, y: pcy + 0.25 + 0.21, w: pcgap * 0.5, h: 0.08 });
      }
      pcx += pcw + pcgap;
    });

    s.addText('TECHNOLOGIES USED', { x: 0.7, y: 4.78, w: 4, h: 0.22, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 9, bold: true, color: C.bodyGray, charSpacing: 1 });
    const chips = ['Zeek', 'Redpanda / Kafka', 'Faust', 'PyTorch', 'FastAPI', 'PostgreSQL', 'Redis', 'Streamlit'];
    let chx = 0.7;
    for (const chip of chips) {
      const w = 0.28 + chip.length * 0.074;
      s.addShape('roundRect', { x: chx, y: 5.02, w, h: 0.34, rectRadius: 0.17, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 } });
      s.addText(chip, { x: chx, y: 5.02, w, h: 0.34, isTextBox: true, margin: 0, align: 'center', valign: 'middle', fontFace: FONT_MONO, fontSize: 8.5, color: C.headlineNavy });
      chx += w + 0.15;
    }

    s.addText('RUNNING IN PARALLEL', { x: 0.7, y: 5.58, w: 4, h: 0.22, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 9, bold: true, color: C.bodyGray, charSpacing: 1 });
    const detectors = ['Flow Autoencoder', 'DGA CNN', 'Port-Scan', 'DDoS-Rate', 'C2-Beacon', 'Exfil-Volume', 'DNS-Behavior'];
    let dx = 0.7;
    for (const d of detectors) {
      const w = 0.28 + d.length * 0.072;
      s.addShape('roundRect', { x: dx, y: 5.82, w, h: 0.34, rectRadius: 0.17, fill: { color: C.cardLight }, line: { color: C.border, width: 1 } });
      s.addText(d, { x: dx, y: 5.82, w, h: 0.34, isTextBox: true, margin: 0, align: 'center', valign: 'middle', fontFace: FONT_MONO, fontSize: 8.5, color: C.headlineNavy });
      dx += w + 0.15;
    }

    // A real, scannable QR code to the public GitHub repo -- ties directly
    // to the CI-gated benchmarks this deck cites, not a decorative box.
    s.addShape('roundRect', { x: 9.3, y: 5.5, w: 3.3, h: 0.85, rectRadius: 0.08, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 } });
    s.addText([
      { text: 'VIEW THE SOURCE\n', options: { bold: true, color: C.headlineNavy, fontSize: 9.5 } },
      { text: 'Full code, tests, and CI-gated benchmarks on GitHub.', options: { color: C.bodyGray, fontSize: 8 } },
    ], { x: 9.48, y: 5.5, w: 2.0, h: 0.85, isTextBox: true, margin: 0, valign: 'middle', fontFace: FONT_BODY, lineSpacing: 10.5 });
    s.addImage({ path: '/Users/chakri/Downloads/sih14-redesign/qr_github.png', x: 11.78, y: 5.565, w: 0.72, h: 0.72 });

    s.addText('Every detector tags its findings with a MITRE ATT&CK technique ID — shown throughout the working dashboard prototype.', {
      x: 0.7, y: 6.38, w: 11.9, h: 0.4, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, italic: true, color: C.bodyGray, lineSpacing: 12.5,
    });
    sihFooter(s, 2);
  }

  // ============================================================
  // PAGE 3 -- Feasibility and Viability
  // ============================================================
  {
    const s = newSlide();
    sihHeader(s);
    eyebrow(s, 'Feasibility and Viability', { x: 0.7, y: 0.95 });
    s.addText('Measured against real attack traffic.', {
      x: 0.7, y: 1.25, w: 11.9, h: 0.5, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 25, bold: true, color: C.headlineNavy,
    });

    // Back to the card system (white panels, soft shadow, bottom-ruled
    // table) -- but each card now carries ONE idea instead of three
    // stacked diagrams. The top icon-flow is gone entirely (it only
    // repeated what the table already says); deployment is one caption
    // line, not a second diagram, so the left card has room to breathe.
    const colY = 1.85, colH = 4.8, colW2 = 5.75;
    const colX = [0.7, 6.85];

    // --- Column 1: Feasibility evidence ---
    {
      const x0 = colX[0];
      s.addShape('roundRect', {
        x: x0, y: colY, w: colW2, h: colH, rectRadius: 0.1, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 },
        shadow: { type: 'outer', color: '9AA3AC', opacity: 0.3, blur: 7, offset: 2, angle: 90 },
      });
      s.addText('FEASIBILITY — REAL VALIDATED RESULTS', { x: x0 + 0.28, y: colY + 0.26, w: colW2 - 0.56, h: 0.28, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 10, bold: true, color: C.headlineNavy, charSpacing: 1 });

      s.addText('98.3% precision · 1.15% FPR', {
        x: x0 + 0.3, y: colY + 0.68, w: colW2 - 0.6, h: 0.34, isTextBox: true, margin: 0,
        fontFace: FONT_HEAD, fontSize: 19, bold: true, color: C.accentBlue,
      });
      s.addText('Composite score, all 7 detectors, measured against real CTU-13 botnet traffic — not synthetic data.', {
        x: x0 + 0.3, y: colY + 1.08, w: colW2 - 0.6, h: 0.4, isTextBox: true, margin: 0,
        fontFace: FONT_BODY, fontSize: 9, color: C.bodyGray, lineSpacing: 12,
      });

      // Per-detector breakdown -- a light, bottom-ruled table (no filled
      // header block, soft zebra rows) instead of a spreadsheet grid.
      const detectorRows = [
        ['Flow Autoencoder', '95.8%', '0.63%'],
        ['DGA Classifier', '84.6%', '13.9%'],
        ['Port-Scan Detection', '99.8%', '0.06%'],
        ['Exfiltration Detection', '100.0%', '0.01%'],
        ['DDoS Detection', '100.0%', '0.00%'],
      ];
      const headCell = (align) => ({ fontSize: 9, fontFace: FONT_MONO, color: C.headlineNavy, bold: true, align, valign: 'middle', fill: { color: 'FFFFFF' }, border: [{ pt: 0, color: 'FFFFFF' }, { pt: 0, color: 'FFFFFF' }, { pt: 1.5, color: C.accentBlue }, { pt: 0, color: 'FFFFFF' }] });
      const rowFill = (i) => ({ color: i % 2 === 0 ? 'FFFFFF' : 'F6F8FA' });
      const rowBorder = [{ pt: 0, color: 'FFFFFF' }, { pt: 0, color: 'FFFFFF' }, { pt: 0.75, color: C.border }, { pt: 0, color: 'FFFFFF' }];
      const rows = [
        [{ text: 'DETECTOR', options: headCell('left') }, { text: 'PRECISION', options: headCell('center') }, { text: 'FPR', options: headCell('center') }],
        ...detectorRows.map(([name, prec, fpr], i) => [
          { text: name, options: { fontSize: 9.5, fontFace: FONT_BODY, color: C.headlineNavy, bold: true, valign: 'middle', fill: rowFill(i), border: rowBorder } },
          { text: prec, options: { fontSize: 9.5, fontFace: FONT_MONO, color: C.good, bold: true, align: 'center', valign: 'middle', fill: rowFill(i), border: rowBorder } },
          { text: fpr, options: { fontSize: 9.5, fontFace: FONT_MONO, color: C.good, bold: true, align: 'center', valign: 'middle', fill: rowFill(i), border: rowBorder } },
        ]),
      ];
      s.addTable(rows, {
        x: x0 + 0.3, y: colY + 1.62, w: colW2 - 0.6,
        colW: [2.55, 1.3, 1.3],
        autoPage: false, rowH: 0.38,
      });

      // Reinforces scale and rigor -- real counts from the full CTU-13
      // suite, not a single curated scenario.
      s.addText([
        { text: 'DATASET SCALE   ', options: { fontFace: FONT_MONO, fontSize: 8, bold: true, color: C.bodyGray, charSpacing: 1 } },
        { text: 'Validated across all 13 CTU-13 scenarios — 18,627 real botnet flows vs. 24,305 real benign flows, not a curated subset.', options: { fontFace: FONT_BODY, fontSize: 9, italic: true, color: C.bodyGray } },
      ], {
        x: x0 + 0.3, y: colY + 4.16, w: colW2 - 0.6, h: 0.55, isTextBox: true, margin: 0, lineSpacing: 12.5,
      });
    }

    // --- Column 2: Challenges & mitigation strategies ---
    {
      const x0 = colX[1];
      s.addShape('roundRect', {
        x: x0, y: colY, w: colW2, h: colH, rectRadius: 0.1, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 },
        shadow: { type: 'outer', color: '9AA3AC', opacity: 0.3, blur: 7, offset: 2, angle: 90 },
      });
      s.addText('CHALLENGES & MITIGATION STRATEGIES', { x: x0 + 0.28, y: colY + 0.26, w: colW2 - 0.56, h: 0.28, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 10, bold: true, color: C.headlineNavy, charSpacing: 1 });

      const rows = [
        ['FiZap', 'High-Volume Traffic Spikes', 'Bounded buffers, backpressure, priority queues.'],
        ['FiLock', 'Encrypted Payloads (Blind Spots)', 'Metadata, timing, flow-shape, and connection-pattern analysis.'],
        ['FiAlertTriangle', 'Alert Fatigue & False Positives', 'Multi-signal correlation, contextual thresholds, and analyst feedback.'],
        ['FiRefreshCw', 'Sensor / Segment Failure', 'Fails closed, not open — a broken detector degrades gracefully instead of blocking the pipeline.'],
      ];
      let ry = colY + 0.82;
      rows.forEach(([icon, title, body], ri) => {
        iconCircle(s, { x: x0 + 0.3, y: ry, size: 0.4, icon, color: ri % 2 === 1 ? C.accentBlue : C.headlineNavy });
        s.addText(title, { x: x0 + 0.82, y: ry - 0.02, w: colW2 - 1.1, h: 0.32, isTextBox: true, margin: 0, fontFace: FONT_HEAD, fontSize: 11.5, bold: true, color: C.headlineNavy, lineSpacing: 13 });
        s.addText(body, { x: x0 + 0.3, y: ry + 0.42, w: colW2 - 0.58, h: 0.5, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, color: C.bodyGray, lineSpacing: 12.5 });
        ry += 1.0;
      });
    }

    s.addText('*Precision/FPR figures are real, measured results — see repository CI-gated benchmarks.', {
      x: 0.7, y: colY + colH + 0.15, w: 11.9, h: 0.24, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 8.5, italic: true, color: C.bodyGray,
    });
    sihFooter(s, 3);
  }

  // ============================================================
  // PAGE 4 -- Impact and Benefits
  // ============================================================
  {
    const s = newSlide();
    sihHeader(s);
    eyebrow(s, 'Impact and Benefits', { x: 0.7, y: 0.95 });
    s.addText('From 100 raw alerts to one readable incident.', {
      x: 0.7, y: 1.22, w: 11.9, h: 0.42, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 21, bold: true, color: C.headlineNavy,
    });

    // Back to the fuller icon + title + one-line body treatment -- each
    // benefit gets its own short explanation, not just a label.
    const sideTop = 1.8, sideBottom = 5.65;

    const leftItems = [
      ['FiClock', 'Faster Triage & Improved Investigation', 'Prioritized incidents instead of isolated alerts, with evidence in one view.'],
      ['FiEye', 'Broader Passive Visibility', 'Monitors unmanaged and unfamiliar devices without active scanning.'],
      ['FiZap', 'One-Click Analyst Actions', 'Acknowledge, mark false positive, or confirm & escalate — instantly.'],
    ];
    let ly = sideTop;
    const lyStep = (sideBottom - sideTop) / leftItems.length;
    for (const [icon, title, body] of leftItems) {
      iconCircle(s, { x: 0.7, y: ly, size: 0.44, icon });
      s.addText(title, { x: 1.3, y: ly - 0.02, w: 3.3, h: 0.44, isTextBox: true, margin: 0, fontFace: FONT_HEAD, fontSize: 11.5, bold: true, color: C.headlineNavy, lineSpacing: 13 });
      s.addText(body, { x: 0.7, y: ly + 0.5, w: 3.9, h: 0.5, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, color: C.bodyGray, lineSpacing: 12.5 });
      ly += lyStep;
    }

    const rightItems = [
      ['FiDatabase', 'Lower Data Burden', 'Uses flow summaries and selective evidence retention, not full payloads.'],
      ['FiLayers', 'Scalable Deployment', 'Extends to multiple institutional locations with minimal redesign.'],
      ['FiCheckCircle', 'Explainable & Correlated Alerts', 'Evidence-based scoring builds analyst confidence.'],
    ];
    let rx = 9.0, ryy = sideTop;
    const ryyStep = (sideBottom - sideTop) / rightItems.length;
    for (const [icon, title, body] of rightItems) {
      iconCircle(s, { x: rx, y: ryy, size: 0.42, icon });
      s.addText(title, { x: rx + 0.56, y: ryy - 0.02, w: 3.1, h: 0.4, isTextBox: true, margin: 0, fontFace: FONT_HEAD, fontSize: 10.8, bold: true, color: C.headlineNavy, lineSpacing: 12 });
      s.addText(body, { x: rx, y: ryy + 0.44, w: 3.85, h: 0.55, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.3, color: C.bodyGray, lineSpacing: 12 });
      ryy += ryyStep;
    }

    // Center: the Kill Chain incident-card mockup.
    const px = 4.72, pw = 3.9, py0 = sideTop;
    s.addShape('roundRect', {
      x: px, y: py0, w: pw, h: sideBottom - sideTop, rectRadius: 0.1, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 },
      shadow: { type: 'outer', color: '9AA3AC', opacity: 0.28, blur: 7, offset: 2, angle: 90 },
    });
    s.addText('Anomalous Flow /\nData Exfiltration', {
      x: px + 0.24, y: py0 + 0.18, w: pw - 0.48, h: 0.5, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 11, bold: true, color: C.headlineNavy, lineSpacing: 13,
    });
    s.addText([
      { text: 'INC-10-0-0-5   ', options: { fontFace: FONT_MONO, color: C.bodyGray } },
      { text: 'CRITICAL', options: { fontFace: FONT_MONO, color: C.critical, bold: true } },
    ], { x: px + 0.24, y: py0 + 0.7, w: pw - 0.48, h: 0.22, isTextBox: true, margin: 0, fontSize: 8 });
    s.addShape('line', { x: px + 0.24, y: py0 + 1.0, w: pw - 0.48, h: 0, line: { color: C.border, width: 1 } });
    s.addText('KILL CHAIN', { x: px + 0.24, y: py0 + 1.08, w: pw - 0.48, h: 0.2, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 7.5, color: C.accentBlue, charSpacing: 1, bold: true });

    const phases = [
      { dot: C.high, threat: 'Anomalous Flow', count: '× 37', meta: 'DL_AUTOENCODER_FLOW_ANOMALY' },
      { dot: C.critical, threat: 'Data Exfiltration', count: '× 63', meta: 'RULE_EXFIL_BYTE_VOLUME', mitre: 'T1048' },
    ];
    let phy = py0 + 1.36;
    phases.forEach((p, i) => {
      s.addShape('ellipse', { x: px + 0.26, y: phy + 0.03, w: 0.11, h: 0.11, fill: { color: p.dot }, line: { type: 'none' } });
      if (i < phases.length - 1) {
        s.addShape('line', { x: px + 0.315, y: phy + 0.16, w: 0, h: 0.55, line: { color: C.border, width: 1.5 } });
      }
      s.addText([{ text: p.threat + '  ', options: { bold: true, color: C.headlineNavy, fontSize: 9.5 } }, { text: p.count, options: { color: C.bodyGray, fontFace: FONT_MONO, fontSize: 8 } }], {
        x: px + 0.48, y: phy - 0.1, w: pw - 0.74, h: 0.26, isTextBox: true, margin: 0,
      });
      s.addText(p.meta, { x: px + 0.48, y: phy + 0.15, w: pw - 0.74, h: 0.3, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 6.5, color: C.bodyGray, lineSpacing: 8 });
      if (p.mitre) {
        s.addShape('roundRect', { x: px + 0.48, y: phy + 0.38, w: 0.55, h: 0.2, rectRadius: 0.04, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 0.75 } });
        s.addText(p.mitre, { x: px + 0.48, y: phy + 0.38, w: 0.55, h: 0.2, isTextBox: true, margin: 0, align: 'center', valign: 'middle', fontFace: FONT_MONO, fontSize: 7.5, color: C.accentBlue });
      }
      phy += 0.72;
    });

    s.addText('Risk Score', { x: px + 0.24, y: py0 + 2.85, w: pw - 0.48, h: 0.2, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 7.5, color: C.bodyGray, charSpacing: 1 });
    s.addText([{ text: '70  ', options: { fontSize: 20, bold: true, color: C.high } }, { text: 'Elevated', options: { fontSize: 9.5, color: C.bodyGray } }], {
      x: px + 0.24, y: py0 + 3.05, w: pw - 0.48, h: 0.32, isTextBox: true, margin: 0,
    });

    // Broader impact -- social / economic / institutional, as the format
    // explicitly asks for.
    s.addText('BROADER IMPACT', { x: 0.7, y: sideBottom + 0.18, w: 6, h: 0.22, isTextBox: true, margin: 0, fontFace: FONT_MONO, fontSize: 9, bold: true, color: C.headlineNavy, charSpacing: 1 });
    const impact = [
      ['FiUsers', 'Social', 'Protects citizen, student, and patient data across schools, hospitals, and government offices.'],
      ['FiTrendingUp', 'Economic', 'Cuts analyst hours and licensing cost versus proprietary SOC tooling — self-hosted and open.'],
      ['FiShield', 'Institutional', 'Strengthens public-sector cyber-defense with an audit trail regulators can inspect.'],
    ];
    const iCol = 11.9 / 3;
    let ix = 0.7;
    const impactY = sideBottom + 0.4;
    for (const [icon, title, body] of impact) {
      iconCircle(s, { x: ix, y: impactY, size: 0.34, icon });
      s.addText(title, { x: ix + 0.44, y: impactY, w: iCol - 0.6, h: 0.3, isTextBox: true, margin: 0, valign: 'middle', fontFace: FONT_HEAD, fontSize: 10, bold: true, color: C.headlineNavy });
      s.addText(body, { x: ix, y: impactY + 0.34, w: iCol - 0.3, h: 0.5, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 9.5, color: C.bodyGray, lineSpacing: 11.5 });
      ix += iCol;
    }
    sihFooter(s, 4);
  }

  // ============================================================
  // PAGE 5 -- Research and References
  // ============================================================
  {
    const s = newSlide();
    sihHeader(s);
    eyebrow(s, 'Research and References', { x: 0.7, y: 0.95 });
    s.addText('Every claim here traces to a published source.', {
      x: 0.7, y: 1.25, w: 11.9, h: 0.45, isTextBox: true, margin: 0,
      fontFace: FONT_HEAD, fontSize: 24, bold: true, color: C.headlineNavy,
    });
    s.addText('Six published sources, 1999–2023 — the research this platform is built on.', {
      x: 0.7, y: 1.72, w: 11.5, h: 0.26, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 11, color: C.bodyGray,
    });

    // Back to the card system: MITRE as its own framework band, the other
    // five sources as one even row of dated cards under a rail.
    s.addShape('roundRect', { x: 0.7, y: 2.05, w: 11.9, h: 0.4, rectRadius: 0.08, fill: { color: C.accentBlueTint }, line: { color: C.border, width: 1 } });
    iconCircle(s, { x: 0.9, y: 2.13, size: 0.26, icon: 'FiTarget', color: C.accentBlue });
    s.addText([
      { text: 'APPLIED THROUGHOUT   ', options: { fontFace: FONT_MONO, fontSize: 8, bold: true, color: C.accentBlue, charSpacing: 1 } },
      { text: 'MITRE ATT&CK® Framework', options: { fontFace: FONT_HEAD, fontSize: 10.5, bold: true, color: C.headlineNavy } },
      { text: '  —  attack.mitre.org, used for every technique tag on this platform.', options: { fontFace: FONT_BODY, fontSize: 9.5, color: C.bodyGray } },
    ], { x: 1.28, y: 2.05, w: 11.1, h: 0.4, isTextBox: true, margin: 0, valign: 'middle' });

    const sources = [
      { year: '1999', icon: 'FiActivity', label: 'Network Monitoring', cite: 'Paxson, “Bro: A System for Detecting Network Intruders in Real-Time,” Computer Networks — the research line Zeek continues.' },
      { year: '2014', icon: 'FiDatabase', label: 'Ground-Truth Attack Data', cite: 'García, Grill, Stiborek & Zunino, “An empirical comparison of botnet detection methods,” Computers & Security (CTU-13 dataset).' },
      { year: '2014', icon: 'FiSearch', label: 'Anomaly Detection', cite: 'Sakurada & Yairi, “Anomaly Detection Using Autoencoders with Nonlinear Dimensionality Reduction,” MLSDA.' },
      { year: '2020', icon: 'FiLock', label: 'Access Model', cite: 'NIST Special Publication 800-207, “Zero Trust Architecture.”' },
      { year: '2023', icon: 'FiKey', label: 'TLS Fingerprinting', cite: 'FoxIO, “JA4+ Network Fingerprinting” — github.com/FoxIO-LLC/ja4.' },
    ];
    const railY = 3.15, cardY = 3.5, cardH = 2.3, cardW = 2.22, gap = 0.2;
    const rowX0 = 0.7, rowX1 = 0.7 + sources.length * cardW + (sources.length - 1) * gap;
    s.addShape('line', { x: rowX0 + cardW / 2, y: railY, w: rowX1 - cardW - rowX0, h: 0, line: { color: C.border, width: 2 } });
    sources.forEach((src, i) => {
      const cardX = rowX0 + i * (cardW + gap);
      const dx = cardX + cardW / 2;
      s.addShape('ellipse', { x: dx - 0.08, y: railY - 0.08, w: 0.16, h: 0.16, fill: { color: C.accentBlue }, line: { color: 'FFFFFF', width: 2 } });
      s.addShape('line', { x: dx, y: railY + 0.08, w: 0, h: cardY - railY - 0.08, line: { color: C.border, width: 1.25 } });
      s.addShape('roundRect', {
        x: cardX, y: cardY, w: cardW, h: cardH, rectRadius: 0.08, fill: { color: 'FFFFFF' }, line: { color: C.border, width: 1 },
        shadow: { type: 'outer', color: '9AA3AC', opacity: 0.25, blur: 5, offset: 2, angle: 90 },
      });
      iconCircle(s, { x: cardX + 0.18, y: cardY + 0.18, size: 0.32, icon: src.icon });
      s.addText(src.year, { x: cardX + 0.58, y: cardY + 0.22, w: cardW - 0.76, h: 0.24, isTextBox: true, margin: 0, valign: 'middle', fontFace: FONT_MONO, fontSize: 11, bold: true, color: C.accentBlue, charSpacing: 1 });
      s.addText(src.label, { x: cardX + 0.18, y: cardY + 0.62, w: cardW - 0.36, h: 0.44, isTextBox: true, margin: 0, fontFace: FONT_HEAD, fontSize: 10.8, bold: true, color: C.headlineNavy, lineSpacing: 12.5 });
      s.addText(src.cite, { x: cardX + 0.18, y: cardY + 1.1, w: cardW - 0.36, h: cardH - 1.26, isTextBox: true, margin: 0, fontFace: FONT_BODY, fontSize: 8, color: C.bodyGray, lineSpacing: 10.5 });
    });

    s.addShape('roundRect', { x: 0.7, y: 6.05, w: 11.9, h: 0.55, rectRadius: 0.08, fill: { color: C.accentBlueTint }, line: { color: C.border, width: 1 } });
    iconCircle(s, { x: 0.95, y: 6.16, size: 0.32, icon: 'FiCheckCircle', color: C.accentBlue });
    s.addText([
      { text: '98.3% precision · 7 detectors · 1.15% FPR', options: { bold: true, color: C.headlineNavy, fontSize: 12 } },
      { text: '  —  composite score, measured against real botnet traffic.', options: { color: C.bodyGray, fontSize: 10 } },
    ], { x: 1.42, y: 6.05, w: 6.7, h: 0.55, isTextBox: true, margin: 0, valign: 'middle', fontFace: FONT_BODY, lineSpacing: 14 });
    s.addShape('ellipse', { x: 9.25, y: 6.3, w: 0.08, h: 0.08, fill: { color: C.accentBlue }, line: { type: 'none' } });
    s.addText('QUIET · RELENTLESS · ALWAYS WATCHING', { x: 9.42, y: 6.05, w: 3.1, h: 0.55, isTextBox: true, margin: 0, valign: 'middle', align: 'right', fontFace: FONT_MONO, fontSize: 7.3, color: C.headlineNavy, charSpacing: 0.4, bold: true });
    sihFooter(s, 5);
  }

  await pres.writeFile({ fileName: '/Users/chakri/Downloads/sih14-redesign/NeuralSOC_SIH_Official_Format.pptx' });
  console.log('done');
}

main().catch(e => { console.error(e); process.exit(1); });
