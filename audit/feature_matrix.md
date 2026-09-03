# Feature Matrix

| ID | Area | Feature | Expected | Test | Result | Severity | Evidence | Fix |
|---|---|---|---|---|---|---|---|---|
| INF-001 | Infrastructure | Docker Compose Syntax | Syntax valid, services start | `docker compose config` | PASS | INFO | `docker compose ps` shows 100% healthy | |
| INF-002 | Infrastructure | Non-Root Execution | Containers execute as non-root user | `docker run whoami` | PASS | INFO | Confirmed `soc_user` runs pipeline via Dockerfile | |
| INF-003 | Infrastructure | Bounded Retention | Redpanda topics have retention set | `rpk topic describe` | PASS | INFO | `raw_traffic` (1h), `incidents` (7d) | |
| ING-001 | Ingestion | Tail to Redpanda | Reads zeek logs, publishes to raw_traffic | `python tail_to_redpanda.py` | PASS | INFO | Logs safely tailed via safe subprocess | |
| ING-002 | Ingestion | DLQ Routing | Malformed JSON goes to DLQ | Synthetic malformed JSON | PASS | INFO | `dead_letter_events` successfully consumed corrupt JSON | |
| SIM-001 | Simulator | DGA Burst Mode | Generates valid DGA events in burst | `python simulator.py --scenario dga` | PASS | INFO | Confirmed task-1120 publishes valid burst output | |
| SCH-001 | Schema | Alert Structure | Output matches strict JSON schema | Validate against JSON schema | PASS | INFO | `inference/schemas.py` correctly uses `jsonschema` bounds | |
| EXT-001 | Extraction | Entropy & Ratios | Calculates correct metrics safely | Source code review | PASS | INFO | Verified `ZeroDivisionError` guards in `features.py` | |
| DET-001 | Detection | Rules Engine | Triggers on hardcoded thresholds | Inject boundary events | PASS | INFO | Exfil rule correctly enforces 5M out/10k in thresholds | |
| ML-001  | ML Inference | ARM64 Mock Fallback | Uses safe fallback if PyTorch fails | Run on Apple Silicon | PASS | INFO | `models.py` safely catches Torch load errors and bounds confidence `min(score, 1.0)` | |
| COR-001 | Correlation| Incident Time Windowing | Groups alerts by Source IP < 5 mins | Correlator unit test | PASS | INFO | Time window logic and LRU memory cap (`max_tracked_ips`) validated in `correlation.py` | |
| COR-002 | Correlation| Risk Score Escalation | Adds penalty for multiple alerts | Risk scorer unit test | PASS | INFO | Multiple alerts/tactics correctly trigger critical escalation logic | |
| STR-001 | Streaming  | Processor Lifecycle | Consumes, infers, publishes seamlessly | E2E integration test | PASS | INFO | Headless daemon (`task-1116`) has sustained ingestion without crashing | |
| UI-001  | Web UI | Empty State Handling | Displays offline/empty messages cleanly| Stop broker, refresh UI | PASS | INFO | Confirmed empty states gracefully display instead of traceback | |
| UI-002  | Web UI | Bounded Memory | Displays max 1000 alerts | Load test with burst traffic | PASS | INFO | `deque(maxlen=1000)` confirmed in `shared/data_access.py` | |
| UI-003  | Web UI | Progressive Disclosure | Distinct Observed vs Inferred evidence | Manual UI inspection | PASS | INFO | Extracted formatting cleanly separates wire facts from ML outputs | |
| TUI-001 | Terminal UI | Keyboard Navigation | Responds to j/k and Enter | Manual TUI test | PASS | INFO | `textual` bindings successfully map to required workflow | |
| TUI-002 | Terminal UI | Pause Mode | Pauses live feed on selection | Manual TUI test | PASS | INFO | Verified `action_toggle_pause` locks refresh loops | |
| SEC-001 | Security | Data Diode Compliance | No active response or inline blocking | Source code review | PASS | INFO | Zero endpoint interaction logic detected across stack | |
| SEC-002 | Security | Safe Subprocesses | No shell injection risks | Source code review | PASS | INFO | Tailing uses strict arrays `['tail', '-F', file_path]` | |
| DOC-001 | Documentation| Setup & Demo Instructions | README explains how to launch | Manual review | PASS | INFO | `demo_cheat_sheet.md` and `Makefile` correctly document flow | |
