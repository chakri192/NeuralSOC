#!/usr/bin/env bash
# verify_multi_node_cluster.sh -- creates a real 3-node kind cluster
# (1 control-plane + 2 workers), installs Cilium as the CNI, applies this
# repo's actual NetworkPolicy/CiliumNetworkPolicy manifests, and proves
# enforcement holds ACROSS NODES.
#
# This repo already did a one-time interactive verification of these
# same policies (see SECURITY.md's "K8s manifest validation and live
# enforcement" section) -- but on a single-node cluster, which can't
# catch a policy that only happened to work because every pod shared one
# node's Cilium agent state. This script forces the test pods onto
# DIFFERENT nodes specifically to close that gap, and is meant to be run
# repeatably (manually, or on a schedule -- see
# .github/workflows/multi-node-cluster-verify.yml) rather than
# interactively once and never again.
#
# Also verifies k8s/hpa.yaml's plain HorizontalPodAutoscaler definitions
# (CPU/memory target utilization) actually trigger scale-out under real
# load, via a synthetic workload with the same resource requests/targets
# -- not the real tsoc-api image, which needs a working Postgres/Redis
# connection to even start. KEDA/Kafka-lag-based scaling (the
# stream-processor's ScaledObject) is NOT covered here -- that needs a
# real KEDA install and a real Kafka deployment generating real consumer
# lag, which is a substantially larger undertaking; explicitly out of
# scope for this pass (see the summary this script prints at the end).
#
# Requires: kind, kubectl, cilium CLI, a running Docker daemon.
set -euo pipefail

CLUSTER_NAME="tsoc-multi-node-verify"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILURES=0

cleanup() {
    echo "==> Cleaning up: deleting kind cluster $CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME" || true
}
trap cleanup EXIT

echo "==> Creating 3-node kind cluster ($CLUSTER_NAME): 1 control-plane + 2 workers, default CNI disabled for Cilium"
cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

echo "==> Installing Cilium (nodes stay NotReady until this completes -- expected)"
cilium install --wait

echo "==> Waiting for all nodes to become Ready now that Cilium (CNI) is up"
kubectl wait --for=condition=Ready nodes --all --timeout=180s

echo "==> Creating tsoc and ingress-nginx namespaces"
kubectl create namespace tsoc
kubectl create namespace ingress-nginx
kubectl label namespace ingress-nginx kubernetes.io/metadata.name=ingress-nginx --overwrite
kubectl label namespace tsoc kubernetes.io/metadata.name=tsoc --overwrite

echo "==> Applying the real NetworkPolicy + CiliumNetworkPolicy manifests"
kubectl apply -n tsoc -f "$REPO_ROOT/k8s/network-policies.yaml"
kubectl apply -n tsoc -f "$REPO_ROOT/k8s/cilium-identity-policy.yaml"

mapfile -t WORKER_NODES < <(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [ "${#WORKER_NODES[@]}" -lt 2 ]; then
    echo "FAIL: expected 2 worker nodes, got ${#WORKER_NODES[@]}: ${WORKER_NODES[*]:-none}"
    exit 1
fi
NODE_A="${WORKER_NODES[0]}"
NODE_B="${WORKER_NODES[1]}"
echo "==> Test pods will be split across $NODE_A and $NODE_B -- cross-node placement is the actual point of this script"

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: stream-processor-test
  namespace: tsoc
  labels:
    app: tsoc-stream-processor
spec:
  nodeName: $NODE_A
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["sleep", "3600"]
---
apiVersion: v1
kind: Pod
metadata:
  name: unlabeled-test
  namespace: tsoc
spec:
  nodeName: $NODE_B
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["sleep", "3600"]
---
apiVersion: v1
kind: Pod
metadata:
  name: tsoc-api-test
  namespace: tsoc
  labels:
    app: tsoc-api
spec:
  nodeName: $NODE_B
  containers:
  # k8s/network-policies.yaml's api-allow rule only permits ingress on
  # port 8000 specifically -- a plain nginx:alpine image listens on 80 by
  # default, which the policy would then (correctly) block regardless of
  # source, silently turning this into a test of nothing. python's stdlib
  # http.server takes the port as a plain argument, so this actually
  # listens where the policy expects.
  - name: http-server
    image: python:3.12-alpine
    command: ["python3", "-m", "http.server", "8000"]
    ports:
    - containerPort: 8000
    readinessProbe:
      tcpSocket:
        port: 8000
      initialDelaySeconds: 2
---
apiVersion: v1
kind: Pod
metadata:
  name: ingress-nginx-test
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
spec:
  nodeName: $NODE_A
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/stream-processor-test -n tsoc --timeout=90s
kubectl wait --for=condition=Ready pod/unlabeled-test -n tsoc --timeout=90s
kubectl wait --for=condition=Ready pod/tsoc-api-test -n tsoc --timeout=90s
kubectl wait --for=condition=Ready pod/ingress-nginx-test -n ingress-nginx --timeout=90s

echo "==> Confirming genuine cross-node placement (not just schema-valid YAML -- the actual point of this phase)"
kubectl get pods -n tsoc -o wide
kubectl get pods -n ingress-nginx -o wide

echo ""
echo "--- Test 1: stream-processor pod -> 169.254.169.254 (cloud metadata range) must time out ---"
if kubectl exec -n tsoc stream-processor-test -- curl -s --max-time 5 -o /dev/null https://169.254.169.254/ 2>/dev/null; then
    echo "FAIL: connection to the cloud metadata range succeeded -- should have timed out"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS: connection to the cloud metadata range timed out as expected"
fi

echo ""
echo "--- Test 2: stream-processor pod -> 1.1.1.1 (arbitrary public IP) must time out ---"
if kubectl exec -n tsoc stream-processor-test -- curl -s --max-time 5 -o /dev/null https://1.1.1.1/ 2>/dev/null; then
    echo "FAIL: connection to an arbitrary public IP succeeded -- egress is wider than the intended toFQDNs allow-list"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS: connection to an arbitrary public IP timed out as expected"
fi

echo ""
echo "--- Test 3: stream-processor pod -> ipwho.is (the actual allow-listed threat-intel API) must succeed ---"
if kubectl exec -n tsoc stream-processor-test -- curl -s --max-time 10 -o /dev/null https://ipwho.is/ 2>/dev/null; then
    echo "PASS: connection to the allow-listed threat-intel API succeeded"
else
    echo "FAIL: connection to ipwho.is failed -- the toFQDNs allow-list may be broken outright, not just overly broad"
    FAILURES=$((FAILURES + 1))
fi

echo ""
echo "--- Test 4: an unlabeled pod (cross-node) must NOT reach the tsoc-api-labeled pod (default-deny ingress) ---"
API_POD_IP=$(kubectl get pod tsoc-api-test -n tsoc -o jsonpath='{.status.podIP}')
if kubectl exec -n tsoc unlabeled-test -- curl -s --max-time 5 -o /dev/null "http://$API_POD_IP:8000/" 2>/dev/null; then
    echo "FAIL: an unlabeled pod reached the tsoc-api-labeled pod -- default-deny ingress is not enforced"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS: an unlabeled pod could not reach the tsoc-api-labeled pod"
fi

echo ""
echo "--- Test 5: an ingress-nginx-labeled pod (cross-node, cross-namespace) MUST reach the tsoc-api-labeled pod ---"
if kubectl exec -n ingress-nginx ingress-nginx-test -- curl -s --max-time 5 -o /dev/null "http://$API_POD_IP:8000/" 2>/dev/null; then
    echo "PASS: the ingress-nginx-labeled pod reached the tsoc-api-labeled pod across nodes and namespaces"
else
    echo "FAIL: the ingress-nginx-labeled pod could not reach the tsoc-api-labeled pod -- the intended allow rule is not enforced cross-node"
    FAILURES=$((FAILURES + 1))
fi

echo ""
echo "==> NetworkPolicy cross-node verification complete: $FAILURES failure(s) out of 5 tests"

echo ""
echo "==> HPA scale-out verification (plain CPU/memory HorizontalPodAutoscaler, not KEDA -- see header)"
echo "==> Installing metrics-server (kind needs --kubelet-insecure-tls; no real kubelet cert chain in a local cluster)"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
kubectl wait --for=condition=Available deployment/metrics-server -n kube-system --timeout=120s

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hpa-verify-workload
  namespace: tsoc
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hpa-verify-workload
  template:
    metadata:
      labels:
        app: hpa-verify-workload
    spec:
      containers:
      - name: burner
        image: busybox:1.36
        # Busy-loop from the start, same idea as k8s/hpa.yaml's
        # tsoc-api-hpa: a low CPU *request* (so a pinned core reads as a
        # huge percentage of it) with a real utilization-based HPA target,
        # not a synthetic replica-count check.
        command: ["sh", "-c", "while true; do :; done"]
        resources:
          requests:
            cpu: 50m
            memory: 32Mi
          limits:
            cpu: 250m
            memory: 64Mi
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: hpa-verify-workload
  namespace: tsoc
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: hpa-verify-workload
  minReplicas: 1
  maxReplicas: 4
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 50
EOF

echo "==> Waiting up to 3 minutes for the HPA to scale hpa-verify-workload beyond 1 replica under real CPU load"
SCALED=0
for i in $(seq 1 18); do
    replicas=$(kubectl get deployment hpa-verify-workload -n tsoc -o jsonpath='{.status.replicas}' 2>/dev/null || echo 0)
    echo "  [$i/18] current replicas: $replicas"
    if [ "${replicas:-0}" -gt 1 ]; then
        SCALED=1
        break
    fi
    sleep 10
done

kubectl get hpa hpa-verify-workload -n tsoc
if [ "$SCALED" -eq 1 ]; then
    echo "PASS: HorizontalPodAutoscaler scaled hpa-verify-workload beyond its starting 1 replica under real CPU load"
else
    echo "FAIL: HorizontalPodAutoscaler never scaled hpa-verify-workload beyond 1 replica within 3 minutes"
    FAILURES=$((FAILURES + 1))
fi

echo ""
echo "=================================================================="
echo "SUMMARY: $FAILURES failure(s) across 6 checks (5 NetworkPolicy + 1 HPA)"
echo "Genuinely NOT covered by this script (see header for why):"
echo "  - KEDA / Kafka-consumer-lag-based scaling (k8s/hpa.yaml's ScaledObject for tsoc-stream-processor)"
echo "  - Kyverno admission control (covered separately, see SECURITY.md; not re-verified multi-node here"
echo "    since admission control doesn't depend on which node a pod lands on)"
echo "  - Real cloud-scale: multi-region, a real load balancer, real production traffic"
echo "=================================================================="

if [ "$FAILURES" -gt 0 ]; then
    exit 1
fi
