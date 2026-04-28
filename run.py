import uvicorn
import sys
sys.path.insert(0, '/root/pentest-manager')
from app.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)

