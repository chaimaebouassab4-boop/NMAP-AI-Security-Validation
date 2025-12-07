#!/bin/bash

echo "🔧 Building NMAP-AI sandbox Docker image..."

docker build -t nmap-ai-sandbox -f Dockerfile .

echo "🎉 Done! Image name: nmap-ai-sandbox"
