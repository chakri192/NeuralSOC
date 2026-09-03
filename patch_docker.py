with open("docker-compose.yml", "r") as f:
    yaml = f.read()

postgres_service = """
  postgres:
    image: postgres:15-alpine
    container_name: soc-postgres
    platform: linux/arm64
    environment:
      POSTGRES_USER: soc_admin
      POSTGRES_PASSWORD: secure_soc_password
      POSTGRES_DB: tsoc
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U soc_admin -d tsoc"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - soc-net
"""

# Inject before the volumes section
volumes_idx = yaml.find("volumes:")
if volumes_idx != -1:
    yaml = yaml[:volumes_idx] + postgres_service + "\n" + yaml[volumes_idx:]
    
    # Also add the postgres-data volume
    yaml = yaml.replace("redpanda-data:\n    driver: local", "redpanda-data:\n    driver: local\n  postgres-data:\n    driver: local")

with open("docker-compose.yml", "w") as f:
    f.write(yaml)
