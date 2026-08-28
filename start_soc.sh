#!/bin/bash

# Navigate to project directory just in case it's run from elsewhere
cd "$(dirname "$0")"

# Execute the gorgeous Rich terminal boot UI
venv/bin/python3 scripts/boot_soc.py
