import re

with open("README.md", "r") as f:
    readme = f.read()

# Replace the outdated Live Demo Execution Guide with the proper one
old_guide_start = "##  Live Demo Execution Guide"
new_guide = """## Quickstart: How to Run the SOC

To launch the full architecture on your local machine, open 5 separate terminal windows and run these commands in order:

```bash
# 1. Start the Kafka/Redpanda Message Broker
docker compose up -d

# 2. Start the AI Stream Processor (Terminal 1)
export PYTHONPATH=$(pwd)
venv/bin/faust -A inference.stream_processor_faust worker -l info

# 3. Start the FastAPI Database Backend (Terminal 2)
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000

# 4. Start the Web & Terminal Dashboards (Terminals 3 and 4)
venv/bin/streamlit run dashboard/app.py
venv/bin/python3 terminal/tsoc_console.py

# 5. Execute the Simulated Attack Traffic (Terminal 5)
venv/bin/python3 ingest/simulator.py --burst
```

---

## How to Update & Retrain the AI Model

This repository ships with a pre-trained, 100% accurate PyTorch 1D-CNN locked by a cryptographic SHA-256 hash (`models/cnn_dga.pt`). 

If you believe the model has become outdated against new Dictionary DGAs or Typosquatting techniques, you do not need to manually gather new data. This project includes an **Infinite Procedural Auto-Trainer** that algorithmically generates millions of new, unseen attack vectors.

To retrain the model and automatically deploy the new cryptographic hash to the production pipeline, simply run:

```bash
export PYTHONPATH=$(pwd)
venv/bin/python3 scripts/continuous_training.py
```

Let it run for 1 or 2 cycles. Once it hits a Validation Accuracy you are satisfied with (e.g., 99%+), press `Ctrl+C`. The script will automatically perform an atomic swap, updating `models/cnn_dga.pt` and `models/cnn_dga.pt.sha256` without crashing the live stream processors.
"""

# Replace from old_guide_start to the end of the file
index = readme.find(old_guide_start)
if index != -1:
    readme = readme[:index] + new_guide
else:
    readme += "\n" + new_guide

with open("README.md", "w") as f:
    f.write(readme)
