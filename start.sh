#!/bin/bash

# ============================================================
# 🔓 Digital Signature Attack Demo - Startup Script
# ============================================================

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🔓 Digital Signature Attack Demo                       ║"
echo "║  RSA-64bit Toy Signature + Shor's Algorithm             ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js tidak ditemukan. Install Node.js >= 16 terlebih dahulu."
    echo "   https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js versi $NODE_VERSION terdeteksi. Minimum versi 16 diperlukan."
    exit 1
fi

echo "✓ Node.js $(node -v) detected"

# Check npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm tidak ditemukan."
    exit 1
fi

echo "✓ npm $(npm -v) detected"
echo ""

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    echo ""
else
    echo "✓ Dependencies already installed"
fi

# Create uploads directory
mkdir -p uploads

echo ""
echo "🚀 Starting server..."
echo "────────────────────────────────────────────────────────────"
echo "   Open browser: http://localhost:3000"
echo "────────────────────────────────────────────────────────────"
echo ""

node server.js
