# Model Rotation Policy
- Load via SHA-256 check on startup.
- On integrity failure: freeze predictions (critical alert) + alert SOC.
- Auto-reload new `.pt` + `.sha256` only when both files match and age < 30 days.
- Rollback to previous validated version if new model fails inference accuracy > 5% drop.
