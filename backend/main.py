import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from backend.api import projects, analysis, findings, reports

app = FastAPI(
    title="VAJRA API",
    description="Verified Autonomous Joint Reasoning & Remediation Architecture for C/C++ Software",
    version="1.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(projects.router)
app.include_router(analysis.router)
app.include_router(findings.router)
app.include_router(reports.router)

@app.get("/")
async def root():
    return {
        "platform": "VAJRA",
        "status": "online",
        "description": "Verified Autonomous Joint Reasoning & Remediation Architecture",
        "supported_languages": ["C", "C++"]
    }

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
