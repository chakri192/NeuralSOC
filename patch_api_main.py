import re

with open("api/main.py", "r") as f:
    api_code = f.read()

# Add schemas import
api_code = api_code.replace("from api import models", "from api import models, schemas\nfrom typing import List")

# Add SlowAPI components
slowapi_init = """
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
"""
api_code = api_code.replace('app = FastAPI(title="T-SOC API", description="Enterprise SOC Backend")', 'app = FastAPI(title="T-SOC API", description="Enterprise SOC Backend")\n' + slowapi_init)

# Inject @limiter.limit and response_model to get_alerts
api_code = api_code.replace(
    '@app.get("/api/v1/alerts")',
    '@app.get("/api/v1/alerts", response_model=List[schemas.AlertResponse])\n@limiter.limit("50/second")'
)

# Also need to inject `request: Request` into get_alerts arguments for SlowAPI
if "def get_alerts(" in api_code:
    api_code = api_code.replace(
        "def get_alerts(limit:",
        "def get_alerts(request: Request, limit:"
    )

# Inject @limiter.limit and response_model to get_stats
api_code = api_code.replace(
    '@app.get("/api/v1/stats")',
    '@app.get("/api/v1/stats", response_model=schemas.StatsResponse)\n@limiter.limit("50/second")'
)

if "def get_stats(" in api_code:
    api_code = api_code.replace(
        "def get_stats(db:",
        "def get_stats(request: Request, db:"
    )

with open("api/main.py", "w") as f:
    f.write(api_code)
