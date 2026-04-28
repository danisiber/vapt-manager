"""
Vercel Python Serverless Function
Exports FastAPI ASGI app for Vercel deployment
"""
import os
import sys

# Ensure project root is in path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Change working directory to project root for template/static paths
os.chdir(ROOT)

from app.main import app

# Vercel Python builder expects 'app' ASGI callable
handler = app
