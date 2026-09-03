with open("k8s/soc-deployment.yaml", "r") as f:
    k8s = f.read()

resources_block = """          resources:
            limits:
              cpu: 500m
              memory: 512Mi
            requests:
              cpu: 250m
              memory: 256Mi
"""

if "name: fastapi" in k8s and "limits:" not in k8s.split("name: fastapi")[1]:
    k8s = k8s.replace("name: fastapi\n          ports:", "name: fastapi\n" + resources_block + "          ports:")

with open("k8s/soc-deployment.yaml", "w") as f:
    f.write(k8s)
