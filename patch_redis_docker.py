with open("docker-compose.yml", "r") as f:
    yaml = f.read()

redis_service = """
  redis:
    image: redis:7-alpine
    container_name: soc-redis
    platform: linux/arm64
    ports:
      - "6379:6379"
    networks:
      - soc-net
"""

# Inject before the volumes section
volumes_idx = yaml.find("volumes:")
if volumes_idx != -1 and "redis:" not in yaml:
    yaml = yaml[:volumes_idx] + redis_service + "\n" + yaml[volumes_idx:]

with open("docker-compose.yml", "w") as f:
    f.write(yaml)
