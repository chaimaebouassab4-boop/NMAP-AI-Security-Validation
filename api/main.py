"""
FastAPI Main Application
========================
Entry point for the NMAP Validation API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import router
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="NMAP AI Security Validation API",
    description="API for validating NMAP commands with AI-powered security analysis",
    version="2.1.0",
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
app.include_router(router)

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "NMAP AI Security Validation API",
        "version": "2.1.0",
        "description": "AI-powered NMAP command validation with autonomous repair",
        "status": "operational",
        "endpoints": {
            "/api/v1/validate": "POST - Validate command with detailed scoring",
            "/api/v1/validate/legacy": "POST - Simple validation format",
            "/api/v1/validate/batch": "POST - Batch validation",
            "/api/v1/repair": "POST - Autonomous repair",
            "/api/v1/health": "GET - Health check",
            "/api/v1/security/rules": "GET - Security rules",
            "/api/v1/stats": "GET - Statistics",
            "/docs": "GET - Interactive API documentation",
            "/redoc": "GET - Alternative documentation"
        }
    }

@app.get("/api/v1/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.1.0",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "nmap-validation-api"
    }

@app.on_event("startup")
async def startup_event():
    """Startup message."""
    print("=" * 80)
    print("🚀 NMAP AI Security Validation API Starting...")
    print("=" * 80)
    print("📚 Swagger UI: http://localhost:8004/docs")
    print("📖 ReDoc: http://localhost:8004/redoc")
    print("=" * 80)
    logger.info("API started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown message."""
    print("\n👋 API Shutting down...")
    logger.info("API shutdown complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004, reload=True)