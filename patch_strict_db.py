with open("api/database.py", "r") as f:
    code = f.read()

# Remove the fallback entirely
code = code.replace(
    'SQLALCHEMY_DATABASE_URL = os.getenv(\n    "DATABASE_URL", \n    "postgresql://soc_admin:secure_soc_password@localhost:5432/tsoc"\n)',
    'SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")\nif not SQLALCHEMY_DATABASE_URL:\n    raise RuntimeError("CRITICAL ERROR: DATABASE_URL environment variable is missing. Halting boot sequence.")'
)

with open("api/database.py", "w") as f:
    f.write(code)
