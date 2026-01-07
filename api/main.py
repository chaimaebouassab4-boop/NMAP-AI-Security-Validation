"""
FastAPI Main Application
========================
Entry point for the NMAP Validation API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import router
from .models import HealthResponse
from datetime import datetime

# Create FastAPI app
app = FastAPI(
    title="NMAP AI Security Validation API",
    description="API for validating NMAP commands with AI-powered security analysis",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router, prefix="/api/v1", tags=["validation"])

@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        timestamp=datetime.utcnow().isoformat()
    )

@app.on_event("startup")
async def startup_event():
    """Startup message."""
    print("="*80)
    print("🚀 NMAP AI Security Validation API Starting...")
    print("="*80)
    print(f"📚 Swagger UI: http://localhost:8004/docs")
    print(f"📖 ReDoc: http://localhost:8004/redoc")
    print("="*80)

@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown message."""
    print("\n👋 API Shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004, reload=True)