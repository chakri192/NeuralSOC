# SIH pitch deck generators

`pptxgenjs` scripts that build the 5-min and 2-min SIH 2026 submission decks (`NeuralSOC_SIH_Deck_5min`/`_2min`, PPTX + PDF).

Kept here as the source of record for the deck content and layout — not a turnkey pipeline. Both scripts hardcode absolute local paths (video render location, output path, QR code image, SIH logo mark) that only resolve on the machine they were built on. To reuse them, replace those paths and run with `node`.

Requires `pptxgenjs`; PDF export via LibreOffice (`soffice --headless --convert-to pdf`).
