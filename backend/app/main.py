from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.api.scan import router as scan_router
from backend.app.database.database import Base, engine
from backend.app.models.scan import ScanResult


app = FastAPI(title="AI DevSecOps Scanner")


# Create database tables
Base.metadata.create_all(bind=engine)


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API routes
app.include_router(scan_router)


# Frontend directory
FRONTEND_DIR = Path(__file__).resolve().parent / "api" / "frontend"


# Serve frontend at /
app.mount(
    "/",
    StaticFiles(
        directory=FRONTEND_DIR,
        html=True
    ),
    name="frontend"
)