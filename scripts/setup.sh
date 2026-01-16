#!/bin/bash
set -e

echo "Setting up Bayzzer environment..."

# 1. Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# 2. Check for GCC
if ! command -v gcc &> /dev/null; then
    echo "Error: gcc is not installed."
    exit 1
fi

echo "Setup complete! You can now run:"
echo "  python run_bayzzer.py --target test_programs/simple_overflow.c"
