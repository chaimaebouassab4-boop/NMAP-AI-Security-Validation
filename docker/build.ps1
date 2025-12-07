Write-Host "Building NMAP-AI sandbox Docker image..." -ForegroundColor Cyan

docker build -t nmap-ai-sandbox -f Dockerfile .

Write-Host "Done! 🎉 Image name: nmap-ai-sandbox" -ForegroundColor Green
