@echo off
echo ==================================
echo Starting NMAP Validation API
echo ==================================

pip install -r requirements-api.txt

echo.
echo Starting server...
echo Swagger UI: http://localhost:8000/docs
echo ==================================
echo.

python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000