import re
import os

# 1. api/database.py - Remove duplicate connect_args
try:
    with open("api/database.py", "r") as f:
        db_content = f.read()
    
    # If there's a collision, let's just make it simple
    if "connect_args={}" in db_content:
        db_content = db_content.replace("connect_args={}", "")
    
    # Ensure there's only one engine definition that is clean
    # I'll just rewrite the engine line if it's messy
    with open("api/database.py", "w") as f:
        f.write(db_content)
except Exception as e: print("db:", e)

# Let's inspect database.py carefully first to avoid blind replace issues
