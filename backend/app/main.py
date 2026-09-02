from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.scan import router as scan_router
from backend.app.database.database import Base, engine
from backend.app.models.scan import ScanResult

app = FastAPI(title="AI DevSecOps Scanner")
Base.metadata.create_all(bind=engine)

@app.get("/")
def home():
    return {
        "message": "AI DevSecOps Scanner API is running"
    }

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scan_router)