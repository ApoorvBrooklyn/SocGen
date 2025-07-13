#!/bin/bash

echo "🔓 Setting up Vulnerable Server for Security Testing"
echo "=================================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Create uploads directory
echo "📁 Creating uploads directory..."
mkdir -p uploads

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 To start the vulnerable server:"
echo "   cd vulnerable-server"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "📍 Server will be available at: http://localhost:5000"
echo "🔓 Admin credentials: admin / admin123"
echo "👤 User credentials: user / password123"
echo ""
echo "⚠️  WARNING: This server contains intentional vulnerabilities!"
echo "   Only use for testing in a controlled environment." 