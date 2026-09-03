import re

# 1. Fix Kubernetes Env Var Mismatch
try:
    with open("k8s/soc-deployment.yaml", "r") as f:
        k8s = f.read()
    k8s = k8s.replace("name: X_API_KEY", "name: TSOC_API_KEY")
    with open("k8s/soc-deployment.yaml", "w") as f:
        f.write(k8s)
except Exception as e:
    print(f"K8s patch error: {e}")

# 2. Fix CI/CD Blocking
try:
    with open(".github/workflows/ci.yml", "r") as f:
        ci = f.read()
    ci = ci.replace("bandit-report.json || true", "bandit-report.json")
    ci = ci.replace('severity: "HIGH,CRITICAL"', 'severity: "HIGH,CRITICAL"\n          exit-code: 1')
    with open(".github/workflows/ci.yml", "w") as f:
        f.write(ci)
except Exception as e:
    print(f"CI patch error: {e}")

# 3. Fix ML Model Simulated Guard
try:
    with open("inference/models.py", "r") as f:
        models = f.read()
    # Remove simulated guard
    models = re.sub(r'\s*if not event\.get\("simulated", False\):\n\s+return ml_alerts\n', '\n', models)
    with open("inference/models.py", "w") as f:
        f.write(models)
except Exception as e:
    print(f"Models patch error: {e}")

print("Integration patches applied.")
