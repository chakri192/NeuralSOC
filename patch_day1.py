import os
import re

with open("api/main.py", "r") as f:
    code = f.read()

# 1. Externalise API_KEY
code = code.replace(
    'API_KEY = "tsoc-prod-key-2026"',
    'import os\nAPI_KEY = os.getenv("TSOC_API_KEY")\nif not API_KEY:\n    raise RuntimeError("TSOC_API_KEY environment variable is required")'
)

# 2. Remove Base.metadata.create_all
code = re.sub(r'Base\.metadata\.create_all\(bind=engine\)\n?', '', code)

# 3. Restrict CORS
code = code.replace(
    'allow_origins=["*"]',
    'allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:8501").split(",")'
)

# 4. Consolidate Stats Query
old_stats = """@app.get("/api/v1/stats")
def get_stats(db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    total = db.query(models.Alert).count()
    critical = db.query(models.Alert).filter(models.Alert.severity == "critical").count()
    high = db.query(models.Alert).filter(models.Alert.severity == "high").count()
    medium = db.query(models.Alert).filter(models.Alert.severity == "medium").count()
    
    return {
        "total_alerts": total, 
        "critical": critical, 
        "high": high,
        "medium": medium
    }"""

new_stats = """from sqlalchemy import func
@app.get("/api/v1/stats")
def get_stats(db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    # Consolidate into a single DB round-trip
    results = db.query(
        func.count(models.Alert.id).label('total'),
        func.sum(func.case((models.Alert.severity == 'critical', 1), else_=0)).label('critical'),
        func.sum(func.case((models.Alert.severity == 'high', 1), else_=0)).label('high'),
        func.sum(func.case((models.Alert.severity == 'medium', 1), else_=0)).label('medium')
    ).first()
    
    return {
        "total_alerts": results.total or 0,
        "critical": results.critical or 0,
        "high": results.high or 0,
        "medium": results.medium or 0
    }"""

code = code.replace(old_stats, new_stats)

with open("api/main.py", "w") as f:
    f.write(code)
